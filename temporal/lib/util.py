import asyncio


async def run_command_with_output(
    command: list[str], cwd: str | None = None, input_data: str | None = None
) -> tuple[str, str, int]:
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
    unique_subdomains = set()
    for item in data:
        unique_subdomains.update(item.splitlines())
    return "\n".join(unique_subdomains)
