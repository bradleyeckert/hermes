# Risk Management

Risk management is a tool for herding cats. It forces developers to consider what can go wrong, what the risks and probabilities of occurence are, and what will be done to mitigate the risks. Besides lowering long-term costs by pushing design decisions up front, Risk Management provides the evidence needed to prove your product is safe. Even if the product does not have compliance needs, a good risk management strategy will pay for itself many times over if the product is the target of a lawsuit.

The main difference from an ad-hoc approach is that Risk Management has defined inputs and outputs guided by a quality standard. For commercial projects, you would use mandatory industry-specific standards (automotive, medical, etc.). If you are making a real product, expect to fork over real money. [ISO/IEC 5055](https://standards.iso.org/ittf/PubliclyAvailableStandards/index.html) is free. The 2021 version has a 23-page list of naughty software practices starting on page 8, which would be useful when designing tests.

Hermes includes tools to build the documentation.

## Traceability Matrix

The top-level output is a traceability matrix (populated with links) in HTML format. The input for the matrix is an HTML template populated with macros whose format is `%macro string%` where the macro string must not contain a `%`. A documentation generation tool evaluates each macro string in a text interpreter to append its own text to the output as the input is parsed.

Purpose:

- Helps identify gaps in testing coverage
- Ensures that all aspects of the software are validated
- Documents test cases, test runs, and test results
- Tracks requirements through development and testing

The HTML template contains a table that is populated at either edit time or run time. It is created with an HTML editor. Don't forget to use a CSS file. The Traceability Matrix is an HTML table. That's why it's called a matrix. The columns of the table implement a risk matrix with built-in test results and links to drill into the tests. The Traceability Matrix may include:

- Risk
- Likelihood
- Impact
- Risk rating
- Response (action)
- Requirement identification codes
- Hyperlinks to higher level documents
- Verification methods
- Stages where verification takes place
- Verification procedure identification codes
- Test cases
- Test runs
- Test results
- Requirements
- Issues

That's a lot of columns. An FDA-style Traceability Matrix has five columns, with hyperlinks to other reports. For example:

| Use Case |  Requirement | SW Specifications | Verification  | Validation |
|----------|--------------|-------------------|---------------|------------|
|          | SR#, SR      | SRS#, SRS         | TC#, Report   | TE#, Report|

**Use Case** Defines the situation in which the software could be potentially used
**Requirement (Design Input)** Defines what the software should do to meet the use cases
**Software Specifications (Design Output)** Defines the technical functionalities of the software that meets the requirements
**Verification** Checks to see if the developed system meets the design specifications
**Validation** Checks to see if the developed system meets the needs of the stakeholders (i.e. use cases).

Individual reports have their own HTML templates. The documentation generator processes them with an `include` macro. 

### How to create a software validation matrix 

Create a validation plan
Define system requirements
Create a validation protocol and test specifications
Test the software
Develop or revise procedures and a final report

