/* ********************************************************
** Copyright   2018, EAB Global, Inc.
** Author      Trace Sinclair on behalf of EAB Global, Inc.
** Version     0.0.1
******************************************************** */

//testing framework
import "mocha";
//assertion language
import { assert } from "chai";
//Promise based child_process library
import { exec } from "child-process-promise";
//cross platform symbols
import * as logSymbols from "log-symbols";
import * as rc from "rc";

/* ********************************************************
** TypeScript type definitions.
******************************************************** */
namespace audit {
	export interface iResolve {
		id: number,
		path: string,
		dev: boolean,
		optional: boolean,
		bundled: boolean
	}

	export interface iAction {
		action: string,
		module: string,
		target: string,
		isMajor: boolean,
		resolves: Array<iResolve>,
		depth?: number
	}

	export interface iFinding {
		version: string,
		path: Array<string>,
		dev: boolean,
		optional: boolean,
		bundled: boolean
	}

	export interface iMetaData {
		module_type: string,
		exploitability: number,
		affected_components: string
	}

	export interface author {
		name: string
	}

	export interface iAdvisory {
		findings: Array<iFinding>,
		id: number,
		created: string,
		updated: string,
		deleted: any,
		title: string,
		found_by?: author,
		reported_by?: author,
		module_name: string,
		vulnerable_versions: string,
		patched_versions: string,
		overview: string,
		recommendation: string,
		references: string,
		access: string,
		severity: string,
		cwe: string,
		metadata: iMetaData,
		url: string
	}

	export interface iAuditReport {
		actions: Array<iAction>,
		advisories: { [key: string]: iAdvisory }
	}
}

const dftConfig = {
	audit: {
		severityToBreak: {
			"prod": "all",
			"dev": "all",
			"optional": "moderate",
			"bundled": "off"
		},
		exclude: []
	}
};

const auditConfig = rc("audit", dftConfig).audit;

//colors
const cYellow: string = "\x1b[33m";
const cBlue: string = "\x1b[34m";
const cRed: string = "\x1b[31m";
const cGray: string = "\x1b[90m";
const cReset: string = "\x1b[0m";
const cRedBG: string = "\x1b[41";

//link symbols to severity
const severitySymbol = {
	high: logSymbols.error,
	moderate: logSymbols.warning,
	low: logSymbols.info
};
//prirotize severities
const severityRank = {
	off: 0,
	high: 1,
	moderate: 2,
	low: 3,
	all: 4
};

//Define test suite for auditing dependencies
suite("Package Audit", function () {

	//define test case for `npm audit`
	test("npm audit", async function () {
		//clear the Mocha timeout for this testcase only
		this.timeout(0);
		let auditPass = true;

		//run npm audit, and collect the results in JSON format
		let auditReport: string = await exec("npm audit --json")
			//process the results
			.then((/*result*/) => {
				//TODO: explore output when no errors are detected
				return "";
			})
			// Ooops we have audit issues
			.catch((error) => {
				//start building the report
				let header: string = `NPM AUDIT FAILED${cReset}\n\n`;
				//deserialize the output gathered from STDOUT
				const auditDetails: audit.iAuditReport = JSON.parse(error.stdout);

				if (auditDetails && auditDetails.actions && auditDetails.actions.length > 0) {
					//return the report
					return header + auditDetails.actions.map((action: audit.iAction): string => {
						//loop over every action item
						//Assume the module and dependancy are the same for the start
						let nameDep: string = action.module;
						let nameModule: string = action.module;

						//build the header for this action item
						let message = `       Vulnerability found under: ${cRed}${nameDep}${cReset}\n`;

						const descriptions = action.resolves
							.filter((vulnerability: audit.iResolve): boolean => {
								const isExcludedId = auditConfig.exclude.indexOf(vulnerability.id) >= 0;
								const isProd = !vulnerability.dev && !vulnerability.optional && !vulnerability.bundled;
								const isDev = vulnerability.dev;
								const isOpt = vulnerability.optional;
								const isBund = vulnerability.bundled;
								const adv = auditDetails.advisories[vulnerability.id.toString()];

								const INCLUDE = (
									!isExcludedId && (
										isProd && severityRank[adv.severity] <= severityRank[auditConfig.severityToBreak.prod] ||
										isDev && severityRank[adv.severity] <= severityRank[auditConfig.severityToBreak.dev] ||
										isOpt && severityRank[adv.severity] <= severityRank[auditConfig.severityToBreak.optional] ||
										isBund && severityRank[adv.severity] <= severityRank[auditConfig.severityToBreak.bundled])
								);
								return INCLUDE;
							})
							//loop over all the items to resolve
							.map((vulnerability: audit.iResolve): number => {
								//check the begining of the path to see if this is our dependency or another packages dependency
								const packagePath: Array<string> = vulnerability.path.split(">");
								if (nameModule != packagePath[0]) {
									//this is another packages dependency
									nameModule = packagePath[0];
								}
								//just return the Advisory ID
								return vulnerability.id;
							})
							//filter the Advisory IDs down to a distinct list
							.filter((adId: number, idx: number, ads: Array<number>): boolean => ads.indexOf(adId) === idx)
							//Sort the unique Advisory IDs in orver of severity
							.sort((a: number, b: number): number => {
								//+N: a comes before b
								// 0: a and b are "equal"
								//-N: b comes before a
								return severityRank[auditDetails.advisories[a.toString()].severity] - severityRank[auditDetails.advisories[b.toString()].severity];
							})
							//Process all the Advisories, gathering basic details
							.map((advisoryId: number): String => {
								//the current Advisory based on ID
								const currAdvisory = auditDetails.advisories[advisoryId.toString()];
								//build the report string
								return `           ${severitySymbol[currAdvisory.severity]} [${cRed}${currAdvisory.title}${cReset}] ${currAdvisory.url}`;
							})
							//conbine everything into a nice string
							.join("\n");

						if (descriptions.length == 0) {
							return "";
						} else {
							auditPass = false;
						}

						//if the advisory is for a dependencies
						if (nameDep != nameModule) {
							//add the dependancy name to the report
							message += `                     ${cRed}${nameDep}${cReset} is used by ${cBlue}${nameModule}${cReset}\n`;
						}

						//build the full report, including the statement to fix
						return `${message}${descriptions}\n         Run ${cRedBG}m${buildResolveStatement(action)}${cReset} to resolve ${action.resolves.length} vulnerabilities\n`;
					}).join("\n") + "     ";
				} else {
					return header + "Error parsing results.  Please rerun testcase, or run npm audit";
				}
			});

		//make sure the audit report is empty
		assert.isOk(auditPass, auditReport);
	});

})


/**
 * Process the action item, and is Advisories.
 *
 * @param {audit.iAction} action - The action item.
 * @returns {string} - The NPM statement to run in order to resolve the Advisories.
 */
function buildResolveStatement(action: audit.iAction): string {
	let statement = "npm ";
	//What action are we doing...use shorthand notations
	if (action.action === "install") {
		statement += "i ";
	} else if (action.action === "update") {
		statement += "up ";
	}

	//see if this is a DEV dependency
	if (isDev(action.resolves)) {
		statement += "-D ";
	}

	//include the package name and version
	statement += `${action.module}@${action.target} `;

	//see if we need to update at a depty
	if (action.depth) {
		//set the dept flag
		statement += `--depth ${action.depth}`;
	}

	return statement;
}


/**
 * Check if this is a DEV only dependency.
 *
 * @param {audit.iResolve} resolves - The array of advisories to resolve.
 * @returns {boolean} - Flag to indicate if this is a Dev dependency.
 */
function isDev(resolves: Array<audit.iResolve>): boolean {
	//check the length of the filter array looking for non-dev dependencies
	return resolves.filter((vulnerability: audit.iResolve): boolean => !vulnerability.dev).length === 0;
}



