#!/usr/bin/env python3

import argparse
import requests
import os
import sqlite3
import sys
import logging
import stat
from datetime import datetime


__maximum_seconds_between_collections = 70
__credentials_file = os.path.expanduser("~/.mathreads_creds")


class MAThreadsError(Exception):
    pass


def authenticate(dp_debug_url, data_dir):
    aux = dp_debug_url.split("/")[0:3]
    aux += ["SASLogon", "v1", "tickets"]
    tickets_url = "/".join(aux)
    credentials = get_credentials()
    username, password = credentials[0], credentials[1]
    r = requests.post(tickets_url, data={"username": username, "password": password})
    st_url = r.headers["Location"]
    # Service URL should always be the original DPDebug URL
    aux = dp_debug_url.split("/")[0:3]
    aux += ["ci65", "DPDebug"]
    service = "/".join(aux) + "/"
    st = requests.post(st_url, data={"service": service}).text
    params = {"ticket": st}
    set_cookie_header = requests.post(dp_debug_url + "/", data={"username": username, "password": password,
                                                                "login": "Submit"}, params=params).headers["Set-Cookie"]
    cookie = {set_cookie_header.split("=")[0]: set_cookie_header.split("=")[1].split("; ")[0]}
    register_for_thread_events(dp_debug_url, cookie, st, data_dir)
    with open(data_dir + "/auth_info", "w") as f:
        f.write(str(cookie) + "," + st)


def is_authenticated(dp_debug_url, data_dir):
    cookie, ticket = get_auth_info(data_dir)
    if cookie is None or ticket is None:
        return False
    params = {"ticket": ticket}
    response = requests.get(dp_debug_url, cookies=cookie, params=params)
    seconds_since_last_run = (datetime.now() - get_last_run(data_dir)).total_seconds()
    if "Please Log In" in response.text or response.status_code != 200 or \
            seconds_since_last_run > __maximum_seconds_between_collections:
        logging.warning("The CI session used in the last execution is no longer valid. The next task reports might be"
                        " imprecise.")
        conn = get_persistence_connection(data_dir)
        conn.cursor().execute("delete from events")
        conn.commit()
        conn.close()
        # Status code 500 usually means the DPDebug session got logged off
        # 401 usually means the session is from before a SASServer6 restart
        if response.status_code not in (500, 200, 401):
            logoff(dp_debug_url, cookie, ticket)
            raise MAThreadsError("error: DPDebug returned HTTP status %s.\n%s" % (response.status_code,
                                                                                  response.text))
        logoff(dp_debug_url, cookie, ticket)
        return False
    return True


def logoff(dp_debug_url, cookie, ticket):
    params = {"ticket": ticket}
    requests.post(dp_debug_url + "/", params=params, cookies=cookie, data={"logout": "Log+Out"})


def get_auth_info(data_dir):
    try:
        with open(data_dir + "/auth_info", "r") as f:
            aux = f.read()
            ticket = aux.split(",")[1]
            aux2 = aux.split(",")[0].split(": ")
            cookie = dict()
            cookie[aux2[0][2:-1]] = aux2[1][1:-2]
            return cookie, ticket
    except FileNotFoundError:
        return None, None


def register_for_thread_events(dp_debug_url, cookie, ticket, data_dir):
    monitor_url = dp_debug_url + "/monitor.jsp"
    params = {"ticket": ticket}
    requests.get(monitor_url, cookies=cookie, params=params)
    update_registry_datetime(data_dir)


def update_registry_datetime(data_dir):
    with open(data_dir + "/registry_datetime", "w") as rd:
        rd.write(str(datetime.now()))


def get_registry_datetime(data_dir):
    with open(data_dir + "/registry_datetime", "r") as rd:
        return datetime.strptime(rd.read(), "%Y-%m-%d %H:%M:%S.%f")


def get_events(dp_debug_url, cookie, ticket):
    events_url = dp_debug_url + "/getEvents.jsp"
    params = {"ticket": ticket}
    return requests.get(events_url, cookies=cookie, params=params).json()


def initialize_data_dir(data_dir):
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    sql_create_table = """ create table if not exists events (
                            id integer primary key,
                            sid text,
                            taskName text,
                            threadName text,
                            sequenceName text,
                            sequenceID text,
                            icon text,
                            action text,
                            target text,
                            createdTime text)"""
    conn = get_persistence_connection(data_dir)
    conn.cursor().execute(sql_create_table)
    conn.close()


def get_persistence_connection(data_dir):
    return sqlite3.connect(data_dir + "/events.db")


def persist_events(events, data_dir):
    for e in events:
        # Skip if it's a stale event from before registry datetime
        if datetime.fromtimestamp(int(e["createdTime"]) // 1000) < get_registry_datetime(data_dir):
            continue
        conn = get_persistence_connection(data_dir)
        cursor = conn.cursor()
        values = e.values()
        cursor.execute("insert into events (sid, taskName, threadName, sequenceName, sequenceID, icon, action, target, "
                       "createdTime) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", tuple(values))
        conn.commit()
        conn.close()


def list_running_tasks(data_dir):
    conn = get_persistence_connection(data_dir)
    cursor_begin = conn.cursor()
    begin_events = cursor_begin.execute("select id, sid, taskName, threadName, action, createdTime from events "
                                        "where action = 'begin' order by createdTime")
    running_tasks = []
    cursor_completed = conn.cursor()
    for b in begin_events:
        completed_events = cursor_completed.execute("select sid, taskName, threadName, action, createdTime from events "
                                                    "where action = 'completed' and threadName = ? and createdTime >= ?"
                                                    " order by createdTime", (b[3], b[5]))
        if not completed_events.fetchone():
            running_tasks.append(b)
    cursor_completed.close()
    conn.close()
    return running_tasks


def test_timeout(data_dir):
    conn = get_persistence_connection(data_dir)
    cursor = conn.cursor()
    result = cursor.execute("select * from events")
    for r in result:
        print(r)


def get_last_run(data_dir):
    with open(data_dir + "/lastrun", "r") as f:
        return datetime.strptime(f.read(), "%Y-%m-%d %H:%M:%S.%f")


def update_last_run(data_dir):
    with open(data_dir + "/lastrun", "w") as f:
        f.write(str(datetime.now()))


def purge_events(events_to_keep, data_dir):
    event_ids = [e[0] for e in events_to_keep]
    query = "delete from events where id not in ({})".format(", ".join(['?'] * len(event_ids)))
    conn = get_persistence_connection(data_dir)
    conn.cursor().execute(query, event_ids)
    conn.commit()
    conn.close()


def get_credentials():
    with open(__credentials_file) as cf:
        permission_mask = oct(os.stat(__credentials_file)[stat.ST_MODE])
        if permission_mask != "0o100600":
            raise MAThreadsError("error: credentials file permissions should be 600.")
        user = cf.readline()[:-1]
        password = cf.readline()[:-1]
    return user, password


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["collect-events", "list-tasks", "count-tasks", "test-timeout"], help="action to be run")
    parser.add_argument("--dp-debug-url", help="DPDebug URL")
    parser.add_argument("--data-dir", help="data directory", required=True)
    args = parser.parse_args()
    dp_debug_url = args.dp_debug_url
    data_dir = args.data_dir
    action = args.action
    try:
        if action == "collect-events":
            if not dp_debug_url:
                raise MAThreadsError("error: you must specify dp-debug-url with collect-events.")
            if dp_debug_url[-1] == "/":
                raise MAThreadsError("error: dp-debug-url should not have a trailing slash.")
            initialize_data_dir(data_dir)
            log_file = data_dir + "/mathreads.log"
            logging.basicConfig(filename=log_file, format="%(asctime)s %(levelname)s %(message)s")
            if not is_authenticated(dp_debug_url, data_dir):
                authenticate(dp_debug_url, data_dir)
            cookie, ticket = get_auth_info(data_dir)
            e = get_events(dp_debug_url, cookie, ticket)
            update_last_run(data_dir)
            persist_events(e["events"], data_dir)
        elif action == "list-tasks":
            running_tasks = list_running_tasks(data_dir)
            print("SID\tTask name\tThread\tDatetime")
            for t in running_tasks:
                print("%s\t%s\t%s\t%s" % (t[1], t[2], t[3],
                                          datetime.fromtimestamp(int(t[5]) // 1000).strftime('%Y-%m-%d %H:%M:%S')))
            purge_events(running_tasks, data_dir)
        elif action == "count-tasks":
            running_tasks = list_running_tasks(data_dir)
            print(len(running_tasks))
            purge_events(running_tasks, data_dir)
        elif action == "test-timeout":
            test_timeout(data_dir)
    except MAThreadsError as v:
        print(v)
        parser.print_usage()
        sys.exit(1)
