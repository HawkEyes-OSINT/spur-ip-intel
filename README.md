# Spur OSINT Bulk IP Checker

A robust Python tool for bulk querying [Spur.us](https://spur.us) IP intelligence via the authenticated web API.  
Designed for OSINT, forensics, and security investigations.

## Features

- **Bulk IP lookup**: Manual entry or CSV upload
- **Deduplication**: Each unique IP is queried only once; results mapped to all input rows
- **Session management**: Handles Spur/Clerk authentication, session expiry, and re-authentication
- **Rate limit handling**: Exponential backoff and automatic pausing on 429 errors
- **Detailed logging**: All actions and errors logged to `spur_osint.log`
- **CSV output**: Results saved as new or extended CSV, including raw Spur JSON
- **Terminal summary**: Prints summary of unique IPs, errors, and major issues at the end

## Warning

**Use this tool with caution.**  
Your Spur.us account can be suspended if usage patterns appear automated or violate Spur's policies.  
Always comply with Spur's terms of service and applicable local laws when using this tool.

## Requirements

- Python 3.7+
- `requests` library

Install dependencies (if needed):

```bash
pip install requests
```

## Prerequisites

- You **must have an active Spur.us account** with valid login credentials (email and password).
- This script does **not** create accounts or handle registration.
- Ensure your credentials are correct before running the script.

## Usage Instructions

Follow these steps to run and use the Spur OSINT Bulk IP Checker script via the command line:

1. **Run the script**

   Execute the script with Python:

   ```bash
   python spur_osint.py
   ```

2. **Login prompt**

   The script will prompt you to enter your Spur.us credentials:

   ```
   Enter Spur username (email):
   ```

   Type your registered Spur.us email address and press Enter.

   ```
   Enter Spur password:
   ```

   Type your Spur.us password and press Enter. (Note: password input is not hidden.)

3. **Choose input method**

   After successful login, you will see:

   ```
   Choose input method for IPs:
   1. Enter IPs manually
   2. Upload CSV file
   3. Exit
   Enter choice (1/2/3):
   ```

   Type `1` to enter IPs manually, `2` to upload a CSV file, or `3` to exit the program, then press Enter.

4. **If you choose manual input (option 1):**

   You will be prompted:

   ```
   Enter IPs separated by space or comma:
   ```

   Type one or more IP addresses separated by spaces or commas, for example:

   ```
   8.8.8.8, 1.1.1.1 192.168.1.1
   ```

   Press Enter to start processing.

5. **If you choose CSV input (option 2):**

   You will be prompted:

   ```
   Enter path to CSV file:
   ```

   Type the full or relative path to your CSV file and press Enter.

   The script will read the CSV and display the column headers:

   ```
   Columns found in CSV:
   1. ip_address
   2. source
   3. timestamp
   Enter the number of the column containing IPs:
   ```

   Type the number corresponding to the column that contains the IP addresses and press Enter.

6. **Processing**

   The script will:

   - Deduplicate IPs and query each unique IP once.
   - Handle session expiration and rate limits automatically.
   - Print progress updates in the terminal, e.g.:

     ```
     Querying unique IP 1 of 100: 8.8.8.8
     Querying unique IP 2 of 100: 1.1.1.1
     ```

7. **CSV output options (only for CSV input)**

   After processing, you will be asked:

   ```
   Choose output option:
   1. Save results to a new CSV
   2. Extend original CSV with results
   Enter choice (1/2):
   ```

   Type `1` to save only the Spur results as a new CSV file, or `2` to add Spur results as new columns to your original CSV, then press Enter.

8. **Completion**

   The script will save the results in the `output` directory and print:

   ```
   Results saved to output/spur_results_manual_YYYYMMDD_HHMMSS.csv
   ```

   or

   ```
   Results saved to output/spur_results_extended_YYYYMMDD_HHMMSS.csv
   ```

9. **Summary**

   Finally, a summary of the run will be printed, for example:

   ```
   === Summary ===
   Total IPs processed (including duplicates): 150
   Unique IPs queried: 100
   IPs with errors or no data: 3
   Re-authentication attempts: 1
   Rate limit pauses: 0
   =================
   ```

10. **Repeat or exit**

    After completion, you will return to the input method menu to run another batch or exit by choosing option `3`.

---

## Output Fields

- `IP`: The queried IP address
- `Raw Spur.US results`: Full JSON response (as string)
- `Identified VPN, Tunnel, Etc.`: Risk tags (if any)
- `IP Type`: Infrastructure type (if available)
- `IP Est. Geolocation`: Country (if available)

## Logging

- All actions, errors, and raw Spur responses are logged to `spur_osint.log` in the script directory.

## Notes

- **Credentials:** Your Spur.us credentials are required for each run. Credentials are not stored.
- **Rate limits:** The script automatically handles rate limits and session expiry, but very large jobs may take time due to Spur's API restrictions.
- **Privacy:** No data is sent anywhere except to Spur.us.

## License

MIT License

## Author

HawkEyes OSINT Tools and Services
