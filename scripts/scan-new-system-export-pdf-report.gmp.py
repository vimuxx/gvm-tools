import datetime
import sys
import time
from argparse import Namespace
from base64 import b64decode
from pathlib import Path

from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    message = """
        This script starts a new scan on the given host.
        It needs one parameters after the script name.

        1. <host_ip>        IP Address of the host system

        Optional a file name to save the pdf in.

                Example:
            $ gvm-script --gmp-username admin --gmp-password admin \
socket --socketpath /tmp/gvm/gvmd/gvmd.sock \
scan-new-system-export-pdf-report.gmp.py <host_ip> [pdf_file]
    """
    if len_args < 1:
        print(message)
        sys.exit()


def create_target(gmp, ipaddress, port_list_id):
    # create a unique name by adding the current datetime
    name = f"Suspect Host {ipaddress} {str(datetime.datetime.now())}"

    response = gmp.create_target(
        name=name, hosts=[ipaddress], port_list_id=port_list_id
    )
    return response.get("id")


def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    name = f"Scan Suspect Host {ipaddress}"
    response = gmp.create_task(
        name=name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    return response.get("id")


def start_task(gmp, task_id):
    response = gmp.start_task(task_id)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    return response[0].text


def check_task_status(task_id):
    while True:
        task = gmp.get_task(task_id=task_id)
        status = task.xpath("/get_tasks_response/task[1]/status/text()")
        progress = task.xpath("/get_tasks_response/task[1]/progress/text()")
        severity = task.xpath("/get_tasks_response/task[1]/last_report/report/severity/text()")

        if status == ['Done']:
            print("Task is Done", "Severity is:", severity)
            break  # Exit the loop when the status is 'Done'
        elif status == ['Stopped']:
            print("Task is Stopped")
            sys.exit()  # Exit the script when the status is 'Stopped'
        else:
            print("Task is:", status, "Progress is:", progress)

        time.sleep(1)  # Wait for 1 second before checking again


def main(gmp: Gmp, args: Namespace) -> None:
    check_args(args)

    ipaddress = args.argv[1]
    port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

    target_id = create_target(gmp, ipaddress, port_list_id)

    full_and_fast_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"
    openvas_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
    task_id = create_task(
        gmp,
        ipaddress,
        target_id,
        full_and_fast_scan_config_id,
        openvas_scanner_id,
    )

    report_id = start_task(gmp, task_id)

    print(
        f"Started scan of host {ipaddress}. "
        f"Corresponding task ID is {task_id}. "
        f"Corresponding report ID is {report_id}"
    )

    check_task_status(task_id);

    if len(args.argv) == 3:
        pdf_filename = args.argv[2]
    else:
        pdf_filename = args.argv[1] + ".pdf"

    pdf_report_format_id = "c402cc3e-b531-11e1-9163-406186ea4fc5"

    response = gmp.get_report(
        report_id=report_id, report_format_id=pdf_report_format_id,
        filter_string="apply_overrides=0 levels=hml min_qod=70"
    )

    report_element = response.find("report")
    # get the full content of the report element
    content = report_element.find("report_format").tail

    if not content:
        print(
            "Requested report is empty. Either the report does not contain any "
            " results or the necessary tools for creating the report are "
            "not installed.",
            file=sys.stderr,
        )
        sys.exit(1)

    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_pdf = content.encode("ascii")

    # decode base64
    binary_pdf = b64decode(binary_base64_encoded_pdf)

    # write to file and support ~ in filename path
    pdf_path = Path(pdf_filename).expanduser()

    pdf_path.write_bytes(binary_pdf)

    print("Done. PDF created: " + str(pdf_path))


if __name__ == "__gmp__":
    # pylint: disable=undefined-variable
    main(gmp, args)
