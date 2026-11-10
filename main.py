from scanner.config import TARGET, START_PATH, USE_DVWA_LOGIN, ACTIVE_CHECKS, SAVE_RESULTS
from scanner.errors import ScanError
from scanner.report import print_report
from scanner.runner import run_scan


def main():
    try:
        result = run_scan(
            TARGET,
            START_PATH,
            dvwa_login=USE_DVWA_LOGIN,
            active=ACTIVE_CHECKS,
            save=SAVE_RESULTS,
        )
    except ScanError as error:
        print("Scan stopped:", error)
        return

    print_report(result["visited"], result["findings"], result["forms"])

    if result["saved_to"]:
        print("\nSaved results to", result["saved_to"])


if __name__ == "__main__":
    main()