# Process Tree Manager (PTM)

**Process Tree Manager (PTM)** is a C-based program that allows users to manage and analyze processes in a Linux system. By providing a root process, the tool can identify process descendants, check their statuses, and send signals like `SIGKILL`, `SIGSTOP`, and `SIGCONT` to manage them. PTM also provides advanced options to identify defunct (zombie) processes, list non-direct descendants, and even kill zombie process parents.

## Features

- **Process Tree Identification**: List PIDs and parent PIDs of processes in a tree rooted at a given root process.
- **Signal Management**: Send signals like `SIGKILL`, `SIGSTOP`, and `SIGCONT` to descendants of a root process.
- **Sibling and Descendant Management**: List sibling processes and categorize them as defunct or not.
- **Orphan Process Detection**: Identify orphaned processes.
- **Zombie Process Handling**: Detect and kill zombie processes and their parents.
- **Flexible Operation Options**: Choose from various options to manage direct/non-direct descendants, grandchildren, and more.

## Usage

### Command Syntax: prc24s [Option] [root_process] [process_id]
- **root_process**: PID of the root process to manage.
- **process_id**: PID of the process to inspect or manage.
- **Option**: A flag that defines the operation (optional).

### Options:

| Option | Description |
|--------|-------------|
| `-dx`  | Kill all descendants of `root_process` using `SIGKILL`. |
| `-dt`  | Send `SIGSTOP` to all descendants of `root_process`. |
| `-dc`  | Send `SIGCONT` to all paused descendants of `root_process`. |
| `-rp`  | Kill `process_id` using `SIGKILL`. |
| `-nd`  | List non-direct descendants of `process_id`. |
| `-dd`  | List direct descendants of `process_id`. |
| `-sb`  | List all sibling processes of `process_id`. |
| `-bz`  | List defunct sibling processes of `process_id`. |
| `-zd`  | List defunct descendants of `process_id`. |
| `-gc`  | List grandchildren of `process_id`. |
| `-sz`  | Show status of `process_id` (Defunct/Not Defunct). |
| `-so`  | Show status of `process_id` (Orphan/Not Orphan). |
| `-kz`  | Kill the parents of all zombie descendants of `process_id`. |


### Example Commands:

1. List the PID and PPID of a process:
    ```bash
    ./prc24s 1009 1004
    ```

2. Kill all descendants of a root process:
    ```bash
    ./prc24s -dx 1004
    ```

3. List non-direct descendants:
    ```bash
    ./prc24s -nd 1004 1005
    ```

4. Check if a process is defunct:
    ```bash
    ./prc24s -sz 1008 1030
    ```

## Compilation

To compile the program, use the following command:

```bash
gcc -o prc24s prc24s.c
