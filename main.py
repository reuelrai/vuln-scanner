from session import make_session
from crawler import crawl
from report import print_report


def main():
    session = make_session()
    print("Session ready.\n")
    visited, all_findings, all_forms = crawl(session)
    print_report(visited, all_findings, all_forms)


if __name__ == "__main__":
    main()