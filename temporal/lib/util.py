import asyncio

from validators import ValidationError, domain, hostname


def validate_input_domain(target: str) -> bool:
    """
    Validates that input string is a valid domain name.
    :param target: string to be validated.
    :return: True if input string is a valid domain name, False otherwise.
    """
    res = domain(target)
    return not isinstance(res, ValidationError)


def validate_input_hostname(target: str) -> bool:
    """
    Validates that input string is a valid hostname.
    :param target: string to be validated.
    :return: True if input string is a valid hostname, False otherwise.
    """
    res = hostname(target)
    return not isinstance(res, ValidationError)


async def run_command_with_output(
    command: list[str], cwd: str | None = None, input_data: str | None = None
) -> tuple[str, str, int]:
    """
    Executes a command as subprocess.
    :param command: Command to be executed represented as a list of strings.
    :param cwd: the current working directory.
    :param input_data: data communicated to a subprocess.
    :return: string representation of stdout and stderr and a return code
    """
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if input_data else None,
        cwd=cwd,
    )

    if input_data:
        stdout, stderr = await process.communicate(input=input_data.encode())
    else:
        stdout, stderr = await process.communicate()

    stdout_str = stdout.decode("utf-8") if stdout else ""
    stderr_str = stderr.decode("utf-8") if stderr else ""

    return stdout_str, stderr_str, process.returncode


def get_unique_subdomains(*data: str) -> str:
    """
    Preprocesses input data to obtain unique subdomains.
    :param data: input to be processed.
    :return: string representation of unique subdomains.
    """
    unique_subdomains = set()
    for item in data:
        unique_subdomains.update(item.splitlines())
    return "\n".join(unique_subdomains)
