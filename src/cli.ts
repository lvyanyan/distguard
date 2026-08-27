#!/usr/bin/env node
import { statSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import mri from 'mri'

import { scanDirectoryDetailed } from './engine/scan'
import { computeExitCode } from './engine/exitCode'
import { RULES } from './rules'
import { renderJson, renderTerminal } from './report'

const pkg = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string }
const VERSION = pkg.version

interface RcConfig {
  allowlist?: string[]
  ignoreRules?: string[]
}

function loadConfig(path?: string): RcConfig {
  const candidate = path ?? '.distguardrc.json'
  try {
    return JSON.parse(readFileSync(candidate, 'utf8')) as RcConfig
  } catch {
    return {}
  }
}

async function main(): Promise<void> {
  const argv = mri(process.argv.slice(2), {
    boolean: ['json', 'help', 'version'],
    string: ['fail-on', 'config'],
    alias: { h: 'help', v: 'version' },
    default: { 'fail-on': 'high' },
  })

  if (argv.help) {
    printHelp()
    return
  }
  if (argv.version) {
    console.log(VERSION)
    return
  }

  const dirArg = argv._[0] ? String(argv._[0]) : '.'
  let root: string
  try {
    root = resolve(dirArg)
    if (!statSync(root).isDirectory()) throw new Error('not a directory')
  } catch {
    console.error(`distguard: '${dirArg}' is not a readable directory`)
    process.exitCode = 2
    return
  }

  const config = loadConfig(argv.config as string | undefined)
  const rules = RULES.filter(rule => !config.ignoreRules?.includes(rule.id))

  const { report, contents } = await scanDirectoryDetailed(root, { rules })
  report.findings = report.findings.filter(
    finding =>
      !config.allowlist?.some(prefix => finding.file.startsWith(prefix)) &&
      !config.ignoreRules?.includes(finding.ruleId),
  )
  for (const key of Object.keys(report.bySeverity) as Array<keyof typeof report.bySeverity>) {
    report.bySeverity[key] = report.findings.filter(f => f.severity === key).length
  }

  if (argv.json) console.log(renderJson(report, VERSION))
  else renderTerminal(report, contents)

  process.exitCode = computeExitCode(report.findings, argv['fail-on'] as string)
}

function printHelp(): void {
  console.log(`distguard — security gate for your build output

Usage: distguard [dir] [options]

Options:
  --fail-on <level>   exit 1 when findings reach this severity
                      (critical|high|medium|low|info, default: high)
  --json              machine-readable output (consumed by CI)
  --config <path>     config file (.distguardrc.json by default):
                      { "allowlist": ["vendor/"], "ignoreRules": ["..."] }
  -v, --version       print version
  -h, --help          this help`)
}

main().catch(error => {
  console.error('distguard crashed:', error instanceof Error ? error.message : error)
  process.exitCode = 2
})
