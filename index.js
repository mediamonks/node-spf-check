'use strict';

const dns = require('dns');
const util = require('util');

const spfParse = require('spf-parse');
const ipaddr = require('ipaddr.js');
const tlsjs = require('tldjs');
const _ = require('lodash');

/** Result messages. */
const messages = {
    None: 'Cannot assert whether or not the client host is authorized',
    Neutral: 'Domain owner has explicitly stated that he cannot or does not want to assert whether or not the IP address is authorized',
    Pass: 'Client is authorized to inject mail with the given identity',
    Fail: 'Client is *not* authorized to use the domain in the given identity',
    SoftFail: 'Domain believes the host is not authorized but is not willing to make that strong of a statement',
    TempError: 'Encountered a transient error while performing the check',
    PermError: 'Domain\'s published records could not be correctly interpreted',
};

/** Result values (ex. {None: 'None', Neutral: 'Neutral', ...}). */
const results = _.mapValues(messages, _.nthArg(1));

class SPFResult {
    constructor(result, message) {
        if (!_.has(results, result)) {
            throw TypeError('Result "' + result + '" not found');
        }

        if (!_.isString(message) || _.isEmpty(message)) {
            message = messages[result];
        }

        this.result = result;
        this.message = message;
    }
}

class SPF {
    constructor(options) {
        this.warnings = [];
        this.queryDNSCount = 0;

        this.options = {
            version: 1,
            ...options,
        };
    }

    async resolveDNS(hostname, rrtype) {
        if (this.queryDNSCount > 9) {
            throw new SPFResult(results.PermError, 'Limit of DNS lookups reached');
        }

        return new Promise((resolve, reject) => {
            dns.resolve(hostname, rrtype, (err, records) => {
                this.queryDNSCount++;

                if (err) {
                    reject(new SPFResult(results.TempError, err.message));
                } else {
                    if (rrtype === 'TXT') {
                        resolve(_.map(records, record => {
                            return _.join(record, '');
                        }));
                    } else {
                        resolve(records);
                    }
                }
            });
        });
    }

    async resolveSPF(hostname, rrtype) {
        // TODO resolve SPF record and use them instead of TXT if exists

        const records = _.filter(await this.resolveDNS(hostname, 'TXT'), record => {
            // Records that do not begin with a version section are discarded.
            return _.startsWith(record, 'v=spf' + this.options.version + ' ');
        });

        if (records.length === 0) {
            throw new SPFResult(results.None, 'Assume that the domain makes no SPF declarations');
        }

        if (records.length > 1) {
            throw new SPFResult(results.PermError, 'There should be exactly one record remaining');
        }

        const parsed = spfParse(records.pop());

        if (parsed.valid === false) {
            throw new SPFResult(results.PermError, 'There shouldn\'t be any syntax errors');
        }

        if (_.has(parsed, 'messages')) {
           const errors = _.filter(parsed.messages, ['type', 'error']);

           if (errors.length > 0) {
               // When multiple parse errors are found, return the first one so
               // they can be fixed one at the time.
               throw new SPFResult(results.PermError, errors.shift().message);
           }

           this.warnings = _.concat(this.warnings, _.map(_.filter(parsed.messages, ['type', 'warning']), 'message'));
        }

        // True when there is an "all" mechanism.
        const catchAll = _.some(parsed.mechanisms, ['type', 'all']);

        // List of parsed/resolved mechanisms to be returned.
        let resolved = [];

        for (let i = 0; i < parsed.mechanisms.length; i++) {
            // Parsed mechanisms to be resolved recursively.
            const mechanism = parsed.mechanisms[i];

            if (mechanism.type === 'a') {
                mechanism.records = await this.resolveDNS(mechanism.value || hostname, rrtype);
            }

            if (mechanism.type === 'mx') {
                // First performs an MX lookup.
                const exchanges = await this.resolveDNS(mechanism.value || hostname, 'MX');

                // Then it performs an address lookup on each MX name returned.
                for (let e = 0; e < exchanges.length; e++) {
                    exchanges[e].records = await this.resolveDNS(exchanges[e].exchange, rrtype);
                };

                mechanism.exchanges = _.sortBy(exchanges, 'priority');
            }

            if (mechanism.type === 'ip4' || mechanism.type === 'ip6') {
                // If ip4-cidr-length is omitted, it is taken to be "/32".
                // If ip6-cidr-length is omitted, it is taken to be "/128".
                if (mechanism.value.indexOf('/') === -1) {
                    mechanism.value += mechanism.type === 'ip4' ? '/32' : '/128';
                }

                try {
                    mechanism.address = ipaddr.parseCIDR(mechanism.value);
                } catch (err) {
                    throw new SPFResult(results.PermError, 'Malformed "' + mechanism.type + '" address');
                }
            }

            if (mechanism.type === 'include') {
                mechanism.includes = await this.resolveSPF(mechanism.value, rrtype);
            }

            if (mechanism.type === 'redirect') {
                if (!catchAll) {
                    // Any "redirect" modifier has effect only when there is
                    // not an "all" mechanism.
                    resolved = _.concat(resolved, await this.resolveSPF(mechanism.value, rrtype));
                }

                continue;
            }

            resolved.push(mechanism);

            if (mechanism.type === 'all') {
                break; // Mechanisms after "all" will never be resolved.
            }
        }

        return resolved;
    }

    async check(ip, domain, sender) {
        if (!ipaddr.isValid(ip)) {
            return new SPFResult(results.None, 'Malformed IP for comparison');
        }

        if (!tlsjs.isValid(domain)) {
            return new SPFResult(results.None, 'No SPF record can be found on malformed domain');
        }

        // If the sender has no localpart, substitute the string "postmaster"
        // for the localpart.
        if (!_.isString(sender)) {
            sender = 'postmaster@' + domain;
        } else if (!_.includes(sender, '@')) {
            sender = 'postmaster@' + sender;
        }

        // List of parsed mechanisms done by `spf-parse` module. Each value is
        // an object that contains type and value.
        let mechanisms;

        // Parsed IP address.
        const addr = ipaddr.parse(ip);

        try {
            mechanisms = await this.resolveSPF(domain,
                // When any mechanism fetches host addresses to compare with
                // given IP, when it is an IPv4 address, A records are fetched,
                // when it is an IPv6 address, AAAA records are fetched instead.
                addr.kind() === 'ipv4' ? 'A' : 'AAAA'
            );
        } catch (err) {
            if (err instanceof SPFResult) {
                return err;
            }

            return new SPFResult(results.TempError, err.message);
        }

        if (mechanisms.length === 0) {
            // This is a last minute check that may never get called because
            // there should always be the version mechanism.
            return new SPFResult(results.TempError);
        }

        try {
            return this.evaluate(mechanisms, addr);
        } catch (err) {
            if (err instanceof SPFResult) {
                return err;
            }

            return new SPFResult(results.PermError, err.message);
        }
    }

    evaluate(mechanisms, addr) {
        // TODO implement exp

        for (let i = 0; i < mechanisms.length; i++) {
            if (this.match(mechanisms[i], addr)) {
                return new SPFResult(mechanisms[i].prefixdesc);
            }
        }

        // If none of the mechanisms match, then returns a result of "Neutral",
        // just as if "?all" were specified as the last directive.
        return new SPFResult(results.Neutral);
    }

    match(mechanism, addr) {
        switch (mechanism.type) {
            case 'version':
                if (mechanism.value !== 'spf' + this.options.version) {
                    throw new SPFResult(results.PermError, 'Version "' + mechanism.value + '" not supported');
                }
                return false;

            case 'a':
                return _.includes(mechanism.records, addr.toString());

            case 'mx':
                for (let i = 0; i < mechanism.exchanges.length; i++) {
                    if (_.includes(mechanism.exchanges[i].records, addr.toString())) {
                        return true;
                    }
                }
                return false;

            case 'ip4':
            case 'ip6':
                return addr.match(mechanism.address);

            case 'include':
                const result = this.evaluate(mechanism.includes, addr);

                if (result.result === results.None) {
                    throw new SPFResult(results.PermError, 'Validation for "include:' + mechanism.value + '" missed');
                }

                return result.result === results.Pass;

            // TODO implement ptr
            // TODO implement exists

            case 'all':
                return true;
        }

        throw new SPFResult(results.PermError, 'Mechanism "' + mechanism.type + '" not supported');
    }
}

module.exports = async function(ip, domain, sender, options) {
    let spf = new SPF(options);
    let res = await spf.check(ip, domain, sender);

    return res.result;
};

module.exports = _.merge(module.exports, results);

module.exports.SPFResult = SPFResult;
module.exports.SPF = SPF;
