# ssh-log-auditor Python script

**ssh-log-auditor ** An open source Python script will detect potential SSH brute-force attacks and creates a CSV report. If the number of failed login attempts from a given IP address exceeds a certain threshold (default value is 5), the script alerts the user and outputs the IP address, username, date, number of failed attempts, and location information to a CSV file (default file name is failed_login_attempts.csv).

Script is created and maintained by [Mohamed Ali](https://twitter.com/MohamedNab1l)

## Screenshots

![Script in action](Screenshot%202023-04-01%20010551.png)
![Example output report](Screenshot%202023-04-01%20011057.png)

## ssh-log-auditor Variables

**login_threshold:** Set the threshold for failed login attempts.
**csv_output_file:** Set the name and path to the CSV output file.
**geoip2_database:** Set the path to the MaxMind GeoIP2 database.

## ssh-log-auditor Requirements

**To run this script, you will need the following:**
Python 3.6 or later installed on your system.
The geoip2 Python package installed. You can install it using pip by running pip install geoip2.
A MaxMind GeoIP2 database file.


## Usage

`python3 ssh-log-auditor.py'`

## ssh-log-auditor Current Version

**1.0.2** released April 1st, 2023

## Support

Feel free to contact [me](https://twitter.com/MohamedNab1l) if you do have any questions or suggestions.


