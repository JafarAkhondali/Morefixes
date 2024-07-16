import psutil

threshold_percent = 85


def is_load_low(check_time):
    cpu_percent = psutil.cpu_percent(check_time)
    mem_percent = psutil.virtual_memory().percent
    return cpu_percent < threshold_percent and mem_percent < threshold_percent


def extract_commit_from_repo(repo_url, cve_id, search_range=None):
    # TODO: Mark processed status

    # Wait for server to calm down
    while not is_load_low(2):
        pass
    pass



