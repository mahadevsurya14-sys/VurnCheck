from config import config

def display_banner() -> None:
    print("=" * 50)
    print(f"                 {config.TOOL_NAME}")
    print("        Web Vulnerability Assessment Tool")
    print("=" * 50)
    print(f"Author  : {config.AUTHOR}")
    print(f"Version : {config.VERSION}")
    print("Mode    : Authorized Security Testing")
    print("=" * 50)
