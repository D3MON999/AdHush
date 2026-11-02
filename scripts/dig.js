#!/usr/bin/env node
// Tiny DNS client for testing: node scripts/dig.js <name> [type] [server] [port] [--tcp]
import { udpExchange, tcpExchange } from '../src/dns/upstream.js';
import { buildQuery, parse, summarizeAnswers, RCODE_NAMES } from '../src/dns/packet.js';
import { RR_TYPES } from '../src/rules/parser.js';

const args = process.argv.slice(2).filter((a) => a !== '--tcp');
const useTcp = process.argv.includes('--tcp');
const [name, type = 'A', server = '127.0.0.1', port = '53'] = args;
if (!name) {
  console.log('usage: node scripts/dig.js <name> [type] [server] [port] [--tcp]');
  process.exit(1);
}
const qtype = RR_TYPES[type.toUpperCase()] ?? Number(type);
const started = Date.now();
try {
  const exchange = useTcp ? tcpExchange : udpExchange;
  const res = parse(await exchange(server, Number(port), buildQuery(name, qtype), 6000));
  console.log(`${name} ${type.toUpperCase()} -> ${RCODE_NAMES[res.rcode]} [${summarizeAnswers(res).join(', ') || 'no answers'}] in ${Date.now() - started} ms${useTcp ? ' (tcp)' : ''}`);
} catch (e) {
  console.log(`${name} ${type} -> ERROR ${e.message}`);
  process.exitCode = 1;
}
