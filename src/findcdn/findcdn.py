#!/usr/bin/env python

"""findcdn is a security research and reporting tool.

findcdn determine what CDN a domain has and prints or exports the results as json.

EXIT STATUS
    This utility exits with one of the following values:
    0   The list of domain's CDNs were successfully exported or printed to a file.
    >0  An error occurred.

Usage:
  findcdn file <fileIn> [options]
  findcdn list  <domain>... [options]
  findcdn (-h | --help)

Options:
  -h --help                    Show this message.
  --version                    Show the current version.
  -o FILE --output=FILE        If specified, then the JSON output file will be
                               created at the specified value.
  -v --verbose                 Includes additional print statements.
  --all                        Includes domains with and without a CDN
                               in output.
  -d --double                  Run the checks twice to increase accuracy.
  -t --threads=<thread_count>  Number of threads, otherwise use default.
  --timeout=<timeout>          Max duration in seconds to wait for a domain to
                               conclude processing, otherwise use default.
  --user_agent=<user_agent>    Set the user agent to use, otherwise
                               use default.
"""

# Standard Python Libraries
import datetime
import json
import os
import sys
from typing import Any, Dict, List

# Third-Party Libraries
import docopt
from schema import And, Or, Schema, SchemaError, Use
import validators


# Internal Libraries
from ._version import __version__
from .cdnEngine import run_checks
from .findcdn_err import FileWriteError, InvalidDomain, NoDomains, OutputFileExists

# Global Variables
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
TIMEOUT = 60  # Time in seconds
THREADS = 0  # If 0 then cdnEngine uses CPU count to set thread count


def write_json(json_dump: str, output: str, verbose: bool, interactive: bool):
    """Write dict as JSON to output file."""
    try:
        with open(output, "x") as outfile:
            outfile.write(json_dump)
    except FileExistsError:
        raise OutputFileExists(output)
    except Exception as e:
        raise FileWriteError(e)


def main(
    domain_list: List[str],
    output_path: str = None,
    verbose: bool = False,
    all_domains: bool = False,
    interactive: bool = False,
    double_in: bool = False,
    threads: int = THREADS,
    timeout: int = TIMEOUT,
    user_agent: str = USER_AGENT,
) -> str:
    """Take in a list of domains and determine the CDN for each return (JSON, number of successful jobs)."""
    # Make sure the list passed is got something in it
    if len(domain_list) <= 0:
        raise NoDomains("error")

    # Validate domains in list
    for item in domain_list:
        if validators.domain(item) is not True:
            raise InvalidDomain(item)

    # Show the validated domains if in verbose mode
    if verbose:
        print("%d Domains Validated" % len(domain_list))

    # Define domain dict and counter for json
    domain_dict = {}
    CDN_count = 0

    # Check domain list
    processed_list, cnt = run_checks(
        domain_list, threads, timeout, user_agent, interactive, verbose, double_in, output_path,
    )

    # Parse the domain data
    for domain in processed_list:
        # Track the count of the domain has cdns
        if len(domain.cdns) > 0:
            CDN_count += 1

        # Setup formatting for json output
        if len(domain.cdns) > 0 or all_domains:
            domain_dict[domain.url] = {
                "IP": str(domain.ip)[1:-1],
                "cdns": str(domain.cdns)[1:-1],
                "cdns_by_names": str(domain.cdns_by_name)[1:-1],
            }

    # Create JSON from the results and return (results, successful jobs)
    json_dict = {}
    json_dict["date"] = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    json_dict["cdn_count"] = str(CDN_count)
    json_dict["domains"] = domain_dict  # type: ignore
    json_dump = json.dumps(json_dict, indent=4, sort_keys=False)

    # Show the dump to stdout if verbose or interactive
    if (output_path is None and interactive) or verbose:
        print(json_dump)

    # Export to file if file provided
    if output_path is not None:
        write_json(json_dump, output_path, verbose, interactive)
    if interactive or verbose:
        print(
            "Domain processing completed.\n%d domains had CDN's out of %d."
            % (CDN_count, len(domain_list))
        )
    if verbose:
        print(f"{cnt} jobs completed!")

    # Return json dump to callee
    return json_dump


def interactive() -> int:
    """Collect command arguments and run the main program."""
    # Obtain arguments from docopt
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    # Check for None params then set default if found
    if args["--user_agent"] is None:
        args["--user_agent"] = USER_AGENT
    if args["--threads"] is None:
        args["--threads"] = THREADS
    if args["--timeout"] is None:
        args["--timeout"] = TIMEOUT

    # Validate and convert arguments as needed with schema
    schema: Schema = Schema(
        {
            "--output": Or(
                None,
                And(
                    str,
                    lambda filename: not os.path.isfile(filename),
                    error='Output file "' + str(args["--output"]) + '" already exists!',
                ),
            ),
            "<fileIn>": Or(
                None,
                And(
                    str,
                    lambda filename: os.path.isfile(filename),
                    error='Input file "' + str(args["<fileIn>"]) + '" does not exist!',
                ),
            ),
            "--threads": And(
                Use(int),
                lambda thread_count: thread_count >= 0,
                error="Thread count must be a positive number",
            ),
            "--timeout": And(
                Use(int),
                lambda timeout: timeout > 0,
                error="The timeout duration must be a number greater than 0",
            ),
            "--user_agent": And(str, error="The user agent must be a string.",),
            "<domain>": And(list, error="Please format the domains as a list."),
            str: object,  # Don't care about other keys, if any
        }
    )
    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        return 1

    # Add domains to a list
    domain_list = []
    if validated_args["file"]:
        try:
            with open(validated_args["<fileIn>"]) as f:
                domain_list = [line.rstrip() for line in f]
        except IOError as e:
            print("A file error occurred: %s" % e, file=sys.stderr)
            return 1
    else:
        domain_list = validated_args["<domain>"]

    # Start main runner of program with supplied inputs.
    try:
        main(
            domain_list,
            validated_args["--output"],
            validated_args["--verbose"],
            validated_args["--all"],
            True,  # Launch in interactive mode.
            validated_args["--double"],
            validated_args["--threads"],
            validated_args["--timeout"],
            validated_args["--user_agent"],
        )
    # Check for all potential exceptions
    except OutputFileExists as ofe:
        print(ofe.message)
        return 1
    except FileWriteError as fwe:
        print(fwe.message)
        return 2
    except InvalidDomain as invdom:
        print(invdom.message)
        return 3
    except NoDomains as nd:
        print(nd.message)
        return 4
    return 0


if __name__ == "__main__":
    """Launch program in interactive mode"""
    sys.exit(interactive())
