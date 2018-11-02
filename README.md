# audit_test
Integrate `npm audit` as a testcase

## Purpose
`npm audit` is a powerful tool that allows developers to automtically check for packages with potential vulnerabilities in dependencies that are included in their project.  This is a test suite (TDD specification) that can be added to your already existing set of test case.

## Motivation
`npm audit` provides a very short report that can be useful for counting potential vulnerabilities, or some very long-winded output that you will be scrolling till the end of time to find the top of.  This will distil down report, and provide the conscise information to easily fix the issues.  In the event that additional information is still needed, the full report can be generated.

## How to use

Below are details on how to use the provided test suites files

### mocha_audit_spec.ts
This is a TypeScript Mocha test suite with 1 test case using TDD style and Chai for assertions

#### Dependencies

The Following command will install the dependencies required for this test suite

`npm i mocha chai child-process-promise log-symbols rc -D`

* mocha
* chai
* child-process-promise
* log-symbols
* rc

#### Bundled Dependencies

The following are other pachages that are required to run this test suite.  Set up for these will not be covered here.

* TypeScript

#### Directions
Add this file to your test directory, or list of test suites to run depending on your configuration

## Configuration

You can add a `.auditrc` file to the root of your project that will allow you to customize some of the behavior of this test package.  Below is the default configuration if no file is found.

```JSON
{
	"audit":{
		"exclude":[],
		"severityToBreak":{
			"prod":"all",
			"dev":"all",
			"optional":"moderate",
			"bundled":"off"
		}
	}
}
```

`audit.exclude` allows you to supply a list of Error IDs that are to be excluded from reporting.  This should not be used long terms, and you should seek to resolve these vulerable dependencies.

`audit.severitToBreak` allows you to controll what level of severity to throw an error for.  possible values are `all`,`low`,`moderate`,`high`,`off`.  The keys in this object are directly related to the scope a dependency exists in.

`prod` : dependencies

`dev` : devDependencies

`optional` : optionalDependencies

`bundled` : bundledDependencies


## Copyright, author, and license
Copyright 2018 EAB Global, Inc.

Author Trace Sinclair on behalf of EAB Global, Inc.

MIT License