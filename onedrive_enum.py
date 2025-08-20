#!/usr/bin/env python3
#
# 2019 @nyxgeek - TrustedSec
# checks for return code from:
# https://acmecomputercompany-my.sharepoint.com/personal/lightmand_acmecomputercompany_com/_layouts/15/onedrive.aspx
#
# Thanks to @jarsnah12 and @initroott for contributions!

import requests
from requests.exceptions import ConnectionError, ReadTimeout, Timeout
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import sqlite3
#import datetime
from datetime import datetime
import os
import sys
import time
import re
import socket
import signal
import threading
import argparse
import subprocess
import mysql.connector
from mysql.connector import errorcode
import configparser
import traceback

############ OUR CONSTANTS HERE:'
onedrive_enum_dir = os.path.dirname(os.path.abspath(__file__))
sqldb_location = onedrive_enum_dir + '/data/onedrive_enum.db'
survey_wordlist = 'USERNAMES/survey_script_top175_multi.txt'
hostname = socket.gethostname()


############ NEW GLOBAL VARIABLES HERE:
skip_tried = False
enable_db = True
rerun = False
exitRequested = False
verbose = False
debug = False
truncate = None


#might move some or all of these down to main
enableKillAfter = False
killafter=10000
environment = "commercial"
endpoint = "sharepoint.com"



print("")
print("*********************************************************************************************************")
print("")
print("                                         ██████               ███                          ")
print("                                        ░░████               ░░░                           ")
print("   ██████    █████████     ███████    ████████   █████████   ████   █████  █████   ███████ ")
print("  ███░░███  ░░███░░░███   ███░░░███  ███░░░███  ░░███░░░███ ░░███  ░░███  ░░███   ███░░░███")
print(" ░███  ░███  ░███  ░███  ░████████  ░███ ░░███   ░███  ░░░   ░███   ░███   ░███  ░████████ ")
print(" ░███  ░███  ░███  ░███  ░███░░░░   ░███ ░░███   ░███        ░███   ░░███  ███   ░███░░░   ")
print(" ░░██████    ████  █████ ░░███████  ░░█████████  ██████      █████   ░░██████    ░░███████ ")
print("  ░░░░░░    ░░░░  ░░░░░   ░░░░░░░    ░░░░░░░░░  ░░░░░░      ░░░░░     ░░░░░░      ░░░░░░░  ")
print("                                                                             ")


print("                                                                             ")
print("   ██████  ████████   █████ ████ █████████████      +-------------------------------------------------+")
print("  ███░░███░░███░░███ ░░███ ░███ ░░███░░███░░███     |               OneDrive Enumerator               |")
print(" ░███████  ░███ ░███  ░███ ░███  ░███ ░███ ░███     |           2023 @nyxgeek - TrustedSec            |")
print(" ░███░░░   ░███ ░███  ░███ ░███  ░███ ░███ ░███     |                 version 2.10                    |")
print(" ░░██████  ████ █████ ░░████████ █████░███ █████    |  https://github.com/nyxgeek/onedrive_user_enum  |")
print("  ░░░░░░  ░░░░ ░░░░░   ░░░░░░░░ ░░░░░ ░░░ ░░░░░     +-------------------------------------------------+")
print("                                                                             ")
print("*********************************************************************************************************")



class UrlChecker:
    """Check URLs and handle associated operations."""
    def __init__(self, tenant_name, domain, environment, endpoint, userdata, appendString, skip_tried, mysql_conf, output):
        self.tenant_name = tenant_name.rstrip().lower()
        self.domain = domain.rstrip().lower()
        self.safe_domain = self.domain.replace(".", "_")
        self.environment = environment
        self.endpoint = endpoint
        self.userdata = userdata
        self.original_userdata = userdata
        self.appendString = appendString
        self.verbose = verbose
        self.debug = debug
        self.skip_tried = skip_tried
        self.errorcount = 0
        self.validcount = 0
        self.currentcount = 0
        self.totalcount = 0
        self.start_unix_time = 0
        self.status = '0'
        self.mysql_host = None
        self.mysql_db = None
        self.mysql_user = None
        self.mysql_pass = None
        self.mysql_port = 3306
        self.currentdir = os.getcwd()

        if output:
            self.output = True
            # Check if the provided output path is absolute
            if os.path.isabs(output):
                # Use the absolute path as is
                self.output_filename = output
            else:
                # Use the current directory and relative path
                self.output_filename = os.path.join(self.currentdir, output)
        else:
            self.output = False

        if mysql_conf:
            self.mysql_enabled = True
            self.get_sql_conf(mysql_conf)
        else:
            self.mysql_enabled = False

        self.tenant_exists = self.test_connect()

    #>>>>> Database Functions

    def sql_create_table(self):
        #if table does not exist
        create_onedrive_enum = f"create table onedrive_enum(email_address text UNIQUE, username text, domain text, tenant text, scrape_date_unix int, environment text);"
        create_onedrive_log = f"create table onedrive_log(ID INTEGER PRIMARY KEY autoincrement, userlist text, domain text, tenant text, environment text, append text, source_host text, deduped int, start_date_unix int, end_date_unix int, found int, errors int);"
        

    def get_sql_conf(self,mysql_conf):
        # this gets the sql configuration and saves it in self
        config = configparser.ConfigParser()
        if verbose:
            print(f"Config File is at {mysql_conf}")

        #read in our config file
        try:
            config.read(mysql_conf)

            try:
                #here we are going to translate the domain name to an IP so we don't have any DNS issues later
                self.mysql_host = socket.gethostbyname(config['mysql']['host'])
                self.mysql_db = config['mysql']['database']
                self.mysql_user = config['mysql']['user']
                self.mysql_pass = config['mysql']['password']
                self.mysql_port = config['mysql']['port']

                if verbose:
                    print(f"Host: {self.mysql_host}:{self.mysql_port}")
                    print(f"Database: {self.mysql_db}")

            except:
                print(f"ERROR: Could not connect to {self.mysql_db} at {self.mysql_host}:{self.mysql_port}. Verify data in config file")
        except:
            print(f"ERROR: Could not read data in config file")


    def run_mysql_query(self, mysql_query):
        # this runs a mysql query
                # now attempt to connect
        try:
            mydb = mysql.connector.connect(
              host=self.mysql_host,
              user=self.mysql_user,
              password=self.mysql_pass,
              database=self.mysql_db,
              port=self.mysql_port
            )
            mydb.autocommit = True
            databaseHelper = mydb.cursor()
            databaseHelper.execute(mysql_query)
            results = databaseHelper.fetchall()
            mydb.close()
            return results

        except mysql.connector.Error as e:
            print("Some SQL Error code in run_mysql_query:", e.errno)        # error number
            print("** Try reducing your number of threads and see if this error disappears. **")
            print("SQLSTATE value:", e.sqlstate) # SQLSTATE value
            print("Error message:", e.msg)       # error message
            print("Error:", e)                  # errno, sqlstate, msg values
            s = str(e)
            print("Error:", s)                   # errno, sqlstate, msg values
            time.sleep(5)


    def run_sqlite_query(self, sqlite_query):
        # this runs a sqlite query
        try:
            conn = sqlite3.connect(sqldb_location)
            if verbose:
                print(f"sqlite query is: {sqlite_query}")
        except:
            print("Error connecting to sqlite db")
 
        try:
            cursor = conn.execute(sqlite_query)
            conn.commit()
            results = cursor.fetchall()
            return results
                    
        except sqlite3.Error as er:
            print("Some SQLite error in run_sqlite_query!")
            print('SQLite error: %s' % (' '.join(er.args)))
            print("Exception class is: ", er.__class__)
            print('SQLite traceback: ')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))
        finally:
            conn.close()


    def sql_check_for_previous_runs(self, userfile):
        if verbose:
            print("Checking for previous runs of this exact combination.")
        try:
            checkLogsQuery = f"SELECT userlist FROM onedrive_log WHERE domain = '{self.domain}' AND tenant = '{self.tenant_name}' AND userlist = '{userfile}' AND environment = '{self.environment}' AND append = '{self.appendString}' AND end_date_unix IS NOT NULL AND end_date_unix != '1337000004';"

            if self.mysql_enabled:
                if debug:
                    print("trying to get length")
                tmprows = len(self.run_mysql_query(checkLogsQuery))
                if debug:
                    print(f"length is {tmprows}")
            else:
                if debug:
                    print("trying to get length")
                tmprows = len(self.run_sqlite_query(checkLogsQuery))
                if debug:
                    print(f"length is {tmprows}")

            if (int(tmprows) > 0):
                if rerun:
                    if verbose:
                        print(f'INFO: This has been run before. However, you have the -r flag specified, RE-RUNNING.\n')
                        pass
                else:
                    print(f'INFO: This has been run before. To force a re-run use the -r flag. Exiting.\n\n')
                    quit()
        except Exception:
            print(f"Error checking for previous runs")


    def sql_check_tried_usernames(self):
        if verbose:
            print("Checking our tried users.")

        checkLogsQuery = f"SELECT userlist FROM onedrive_log WHERE domain = '{self.domain}' AND tenant = '{self.tenant_name}' AND environment = '{self.environment}' AND append = '{self.appendString}' AND end_date_unix IS NOT NULL AND end_date_unix != '1337000004';"

        if verbose:
            print(checkLogsQuery)

        try:
            if self.mysql_enabled:
                result = self.run_mysql_query(checkLogsQuery)
            else:
                result = self.run_sqlite_query(checkLogsQuery)
            return result
        
        except:
            print(f"Error checking for tried usernames")


    def sql_log_current_run(self, userlist):
        if enable_db:
            if verbose:
                print("Logging current run")
            self.start_unix_time = str(int(time.time()))
            if self.skip_tried:
                deduped = '1'
            else:
                deduped = '0'               
            try:
                insertLogsQuery = f"INSERT INTO onedrive_log (tenant, domain, userlist, start_date_unix, environment, append, source_host, deduped) VALUES ('{self.tenant_name}','{self.domain}','{userlist}','{self.start_unix_time}','{self.environment}','{self.appendString}','{hostname}','{deduped}');"
                if debug:
                    print(insertLogsQuery)

                if self.mysql_enabled:
                    self.run_mysql_query(insertLogsQuery)
                else:
                    self.run_sqlite_query(insertLogsQuery)
            except:
                print("Some SQL or SQLite error in sql_log_current_run! Maybe write some better logging next time.")


    def sql_insert_user(self, email_address, username, domain, tenant, currenttime, environment):
        try:
            if self.mysql_enabled:
                sql_query = f"INSERT IGNORE INTO onedrive_enum (email_address,username, domain, tenant, scrape_date_unix, environment) VALUES ('{email_address}','{username}','{domain}','{tenant}','{currenttime}','{environment}');"
                if debug:
                    print(sql_query)
                self.run_mysql_query(sql_query)
            else:
                sql_query = f"INSERT OR IGNORE INTO onedrive_enum (email_address,username, domain, tenant, scrape_date_unix, environment) VALUES ('{email_address}','{username}','{domain}','{tenant}','{currenttime}','{environment}');"
                if debug:
                    print(sql_query)
                results = self.run_sqlite_query(sql_query)
        except:
            print("Some SQL or SQLite error in sql_insert_user! Maybe write some better logging next time.")


    def sql_log_completed_run(self, userlist):
        #print(self.status)
        if self.status != '0':
            print("Status is {0}".format(self.status))
            end_unix_time = self.status
        else:
            end_unix_time = str(int(time.time()))

        if enable_db:
            if verbose:
                print("Logging current run as complete")
            try:
                logCompletedLogsQuery = f"UPDATE onedrive_log SET end_date_unix = {end_unix_time}, found = {self.validcount}, errors = {self.errorcount} WHERE  domain = '{self.domain}' AND userlist = '{userlist}' AND tenant = '{self.tenant_name}' AND start_date_unix = '{self.start_unix_time}';"
                if debug:
                    print(logCompletedLogsQuery)
                if self.mysql_enabled:
                    self.run_mysql_query(logCompletedLogsQuery)
                else:
                    self.run_sqlite_query(logCompletedLogsQuery)
            except:
                print("Some SQL or SQLite error in sql_log_completed_run! Maybe write some better logging next time.")


    def sql_export_valid_users(self):
        if enable_db:
            if verbose:
                print("Exporting users")
            try:
                getUsersQuery = f"SELECT email_address FROM onedrive_enum WHERE domain = '{self.domain}';"

                if verbose:
                    print(getUsersQuery)
                if self.mysql_enabled:
                    results = self.run_mysql_query(getUsersQuery)
                else:
                    results = self.run_sqlite_query(getUsersQuery)

                resultcount = len(results)
                now = datetime.now()
                formatted_date = now.strftime("%Y%m%d")
                output_filename = f'emails_{self.domain}_{formatted_date}.txt'
                with open(output_filename, 'w') as f:  # 'w' means write mode which overwrites existing contents
                    for user in results:
                        f.write(user[0] + '\n')  # write each email on a new line
                print(f"{resultcount} emails have been written to {output_filename}")
            except:
                print("Some SQL or SQLite error in sql_export_valid_users! Maybe write some better logging next time.")


    #>>>>> requests special function
    def requests_retry_session(self,
        retries=4,
        backoff_factor=1.5,
        status_forcelist=(500, 502, 504),
        session=None,
        ):
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session


    #>>>>> OneDrive Lookup Functions

    def check_url(self, username):

        # If this pause file exists, we wait. This way we can remotely push a pause file out to halt all operations temporarily
        if (os.path.isfile("/tmp/PAUSEFILE")):
            while (os.path.isfile("/tmp/PAUSEFILE")):
                currenttime=datetime.now()
                print(f'\r        {currenttime.strftime("%c")}: PAUSE FILE FOUND: Sleeping ...            \r', end='', flush=True)
                time.sleep(10)
            print("\n")


        """Check a URL and handle associated operations."""
        username = username.rstrip()
        safeusername = (username).replace(".","_")
        if ( "@" in safeusername ):
            if verbose:
                print("Email address format detected, converting to username format")
            self.safe_domain = safeusername.split("@")[1]
            safeusername = safeusername.split("@")[0]

        safeusername = safeusername + self.appendString

        url = f'https://{self.tenant_name}-my.{self.endpoint}/personal/{safeusername}_{self.safe_domain}/_layouts/15/onedrive.aspx'
        # Code to check the URL, handle request and process response
        if debug:
            print("Url is: %s" % url)

        requests.packages.urllib3.disable_warnings()

        #self.currentcount+=1
        lock = threading.Lock()
        try:
            r = self.requests_retry_session().head(url, timeout=8.0)
            #print("Status code is: {}".format(r.status_code))
            status_code = str(r.status_code)
            if status_code in ['404', '301', '302']:
                if verbose:
                    print(f'[-] [{status_code}] INVALID USERNAME FOR {self.tenant_name},{self.domain} - {username}, username:{username}@{self.domain}')
            elif status_code in ['401', '403']:
                currenttime = str(int(time.time()))
                self.validcount+=1

                if self.output:
                    with lock:
                        with open (self.output_filename, "a") as output_file:
                            output_text = f'{username}@{self.domain}'
                            output_file.write(output_text + '\n')

                print(f'[-] [{status_code}] VALID USERNAME FOR {self.tenant_name},{self.domain} - {username}, username:{username}@{self.domain}')
                reconstructed_email = username.replace("_",".") + "@" + self.domain
                self.sql_insert_user(reconstructed_email, username, self.domain,self.tenant_name,currenttime,self.environment)
                pass
            else:
                print(f'[?] [{status_code} UNKNOWN RESPONSE FOR {self.tenant_name},{self.domain} - {username}, username:{username}@{self.domain}')
                self.errorcount+=1
            self.currentcount+=1

            # print our bottom status bar - thanks for the idea, TREVORspray!
            print(f'\r        {self.currentcount} / {self.totalcount} tested,  {self.validcount} valid,  {self.errorcount} errors\r', end='', flush=True)

        except requests.ConnectionError as e:
            self.errorcount += 1
            if verbose:
                print("Error: %s" % e)
            print("Encountered connection error. Let's sleep on it.")
            time.sleep(3)
        except requests.Timeout as e:
            self.errorcount += 1
            if verbose:
                print("Error: %s" % e)
            print("Read Timeout reached, sleeping for 3 seconds")
        except requests.RequestException as e:
            self.errorcount += 1
            if verbose:
                print("Error: %s" % e)
            print("Request Exception - weird. Gonna sleep for 3")
        except Exception as e:
            self.errorcount += 1
            print("Well, I'm not sure what just happened. Onward we go...")
            print(e)

    def check_user(self):
        """Check a specific user."""
        print("In check_user")
        self.check_url(self.userdata)

    def check_user_file(self):
        """Check all users from a file."""
        if verbose:
            print("Our file is {}".format(self.userdata))
        
        print(f"\nBeginning enumeration of https://{self.tenant_name}-my.sharepoint.com/personal/USER_{self.safe_domain}/")
        print("--------------------------------------------------------------------------------------------------------")

        self.sql_check_for_previous_runs(self.userdata)
        self.sql_log_current_run(self.userdata)

        if self.skip_tried:
            print("Dedupe enabled... Starting dedupe:")
            self.checkTriedUsernames(self.userdata)
            #self.checkTriedUsernames(self.userdata, self.tenant_name, self.domain)
        else:
            originalCount = subprocess.run(['wc', '-l', self.userdata], capture_output=True, text=True)
            self.totalcount = int((originalCount.stdout).split()[0])

        if self.totalcount == 0:
            self.status = "1337000003"
            self.sql_log_completed_run(self.userdata)
            exit()


        f = open(self.userdata)
        listthread=[]
        for userline in f:
            global exitRequested
            if exitRequested:
                print("\nOkay, letting a few threads wrap up and then we are out of here\n")

                # we will always have at 1 thread -- us
                while int(threading.active_count()) > 1:
                    print("\n{0} thread remaining: Closing down gracefully.\n".format(int(threading.active_count())))
                    time.sleep(5)
                print("")

                print("MARK IT A ZERO! We are gonna put in 1337000004 as our end time to denote a CANCEL")
                self.status = "1337000004"
                sys.exit(0)
            while int(threading.active_count()) > int(thread_count):
                #print "We have enough threads, sleeping."
                time.sleep(1)

            #print "Spawing thread for: " + userline + " thread(" + str(threading.active_count()) +")"
            x = threading.Thread(target=self.check_url, args=(userline,))

            listthread.append(x)
            x.start()

        f.close()


        for i in listthread:
            i.join()

        print("\n\nOneDrive Enumeration Complete\n")

        # log the completion to our db
        self.sql_log_completed_run(self.userdata)


    def test_connect(self):
        """Test the connection by checking a test URL."""
        url = f'https://{self.tenant_name}-my.{self.endpoint}/personal/TESTUSER_{self.safe_domain}/_layouts/15/onedrive.aspx'
        requests.packages.urllib3.disable_warnings()

        try:
            r = requests.head(url, timeout=10.0)
        except requests.ConnectionError as e:
            if verbose:
                print("%s" % e)
            print("Tenant does not exist - please specify tenant with -t option")
            return False
        if r.status_code:
            if verbose:
                print(f"INFO: Connection to https://{self.tenant_name}-my.sharepoint.com was successful...")
            return True
        else:
            print("Could not reach %s" % url)
            return False

    def checkTriedUsernames(self, userlist):

        tmp_tried_users = "/tmp/onedrive_enum.tried.users"
        tmp_incoming_users = "/tmp/onedrive_enum.unknown.users"
        tmp_untried_users = "/tmp/onedrive_enum.untried.users"



        if verbose:
            print("Sorting our incoming list...")
        os.system(f'cat {userlist} | sort -u  > {tmp_incoming_users}')
        if verbose:
            print("Sort complete.")

        originalCount = subprocess.run(['wc', '-l', tmp_incoming_users], capture_output=True, text=True)
        oCountText = int((originalCount.stdout).split()[0])
        if oCountText == 0:
            print("Incoming file is empty. Exiting.")
            self.status = "1337000003"
            if enable_db:
                self.sql_log_completed_run(self.userdata)
            exit()
        else:
            if verbose:
                print(f"Count is {oCountText}")

        result = self.sql_check_tried_usernames()
        # we need this to be in a format where 'cat' can read it in, space separated values -- 'USERFILES/test1.txt USERFILES/test2.txt'
        list_of_files = ""

        for tmpfile in result:
            if debug:
                print(tmpfile[0])
            list_of_files += f"{tmpfile[0]} "

        if debug:
            print(list_of_files)


        if len(list_of_files) == 0:
            print("This is our first run. No need to de-dupe.")
            self.totalcount = oCountText
            return

        print("Creating a list of all usernames that have ever been attempted with this tenant/domain. This might take a minute... or 5. ")
        os.system(f'cat {list_of_files} | sort -u  > {tmp_tried_users}')
        if verbose:
            print("List complete.")

        os.system(f'comm -13 {tmp_tried_users} {tmp_incoming_users} > {tmp_untried_users}')

        newCount = subprocess.run(['wc', '-l', tmp_untried_users], capture_output=True, text=True)
        nCountText = int((newCount.stdout).split()[0])

        #if verbose:
        print(f'We have reduced the count from {oCountText} to {nCountText}')

        if nCountText == 0:
            print("We have reduced our count to zero due to previous runs. Marking this wordlist as done!")
            status = "1337000003"
            if enable_db:
                #self.logCompleteCurrentRunNew(userlist, self.tenant_name, self.domain, status)
                self.sql_log_completed_run(self.userdata)
            exit()

        #update our instance data
        self.totalcount = nCountText
        self.userdata = tmp_untried_users

class TenantDiscovery:
    """Discover Azure AD tenant names via SharePoint URL pattern testing.
    
    This class attempts to discover the Office 365 tenant name for a given domain by:
    1. Generating potential tenant name patterns based on domain and brand name
    2. Testing each pattern against SharePoint URLs to see if the tenant exists
    3. Verifying ownership by confirming the tenant ID matches via OpenID configuration
    """
    
    # Status constants
    VERIFIED = 'verified'          # SharePoint exists AND ownership verified via OpenID
    TIMEOUT = 'timeout'            # DNS exists but slow/timeout  
    DNS_FAIL = 'dns_fail'          # DNS doesn't resolve
    NO_SHAREPOINT = 'no_sharepoint'  # Other HTTP codes
    ERROR = 'error'                # Unexpected error
    
    # Timeout constants
    DEFAULT_TIMEOUT = 8
    RETRY_TIMEOUT = 15
    
    def __init__(self, verbose=False, endpoint='sharepoint.com'):
        """Initialize the TenantDiscovery instance.
        
        Args:
            verbose: Enable debug output
            endpoint: SharePoint endpoint to test against (default: sharepoint.com)
        """
        self.verbose = verbose
        self.endpoint = endpoint
    
    def discover_tenant(self, domain, tenant_id=None, brand_name=None):
        """Discover the Azure AD tenant name for a domain.
        
        Args:
            domain: The domain to discover tenant for
            tenant_id: Optional pre-fetched tenant ID (will lookup if not provided)
            brand_name: Optional pre-fetched brand name (will lookup if not provided)
        
        Returns: (tenant_name, status) or (None, None) if not found
                 Status is 'verified' only if both SharePoint exists AND ownership is confirmed
        """
        # Get tenant info from Azure endpoints if not provided
        if tenant_id is None:
            tenant_id = get_tenant_id(domain)
        if brand_name is None:
            brand_name = get_tenant_brand_name(domain)
        
        if not (brand_name or tenant_id):
            return (None, None)
        
        # Generate and test patterns
        patterns = self._generate_patterns(domain, brand_name)
        result = self._test_all_patterns(patterns, domain, tenant_id)
        
        return result if result else (None, None)
    
    # Pattern Generation
    
    def _generate_patterns(self, domain, brand_name=None):
        """Generate potential tenant name patterns in priority order."""
        patterns = []
        seen = set()
        
        def clean_text(text):
            """Remove non-alphanumeric characters and lowercase"""
            if not text:
                return ''
            return ''.join(c for c in text.lower() if c.isalnum())
        
        def add_pattern(pattern):
            """Add pattern if not seen before"""
            if pattern and pattern not in seen:
                patterns.append(pattern)
                seen.add(pattern)
        
        # Process brand name if provided (highest priority)
        if brand_name:
            # Full brand name cleaned
            add_pattern(clean_text(brand_name))
            
            # First word of brand name
            words = brand_name.split()
            if words:
                add_pattern(clean_text(words[0]))
        
        # Domain-based patterns
        domain_lower = domain.lower()
        domain_prefix = domain_lower.split('.')[0]
        
        # Full domain without dots (e.g., 'example.com' -> 'examplecom')
        add_pattern(clean_text(domain_lower))
        
        # Domain prefix cleaned (e.g., 'ex-ample.com' -> 'example')
        domain_prefix_clean = clean_text(domain_prefix)
        add_pattern(domain_prefix_clean)
        
        # Common suffixes to try with the domain prefix
        if domain_prefix_clean:
            for suffix in ['365', 'prod', '0', '1']:
                add_pattern(f'{domain_prefix_clean}{suffix}')
        
        return patterns
    
    def _test_all_patterns(self, patterns, domain, tenant_id=None):
        """Test patterns until verified match found. Returns (tenant, status) or None.
        
        A pattern is considered 'verified' only if:
        1. SharePoint URL confirms the tenant exists (403/404/401/302)
        2. OpenID configuration confirms the tenant belongs to the domain's tenant ID
        """
        timeout_patterns = []
        
        # First pass: test all patterns with standard timeout
        for pattern in patterns:
            result = self._test_single_pattern(pattern, domain, tenant_id)
            if result:
                _, verification_type = result
                if verification_type == 'verified':
                    return (pattern, self.VERIFIED)
                elif verification_type == 'timeout':
                    timeout_patterns.append(pattern)
                # Ignore unverified patterns - we only return verified ones
        
        # Second pass: retry timeouts with longer timeout
        if timeout_patterns:
            result = self._retry_timeout_patterns(timeout_patterns, domain, tenant_id)
            if result:
                return result
        
        self._log(f"No verified pattern found for {domain}")
        return None
    
    # Pattern Testing
    
    def _test_single_pattern(self, pattern, domain, tenant_id):
        """Test a single pattern and categorize the result.
        
        Returns: (status, verification_type) where verification_type is:
            - 'verified': Pattern exists and ownership confirmed
            - 'unverified': Pattern exists but ownership not confirmed  
            - 'timeout': Pattern timed out
            - None: Pattern doesn't exist
        """
        status = self._verify_pattern(pattern, domain)
        
        if status != self.VERIFIED:
            if status == self.TIMEOUT:
                self._log(f"{pattern} timed out (will retry if no verified match)")
                return (status, 'timeout')
            return None
        
        # Pattern exists in SharePoint - verify ownership if possible
        if not tenant_id:
            self._log(f"Pattern {pattern} exists (no tenant ID for ownership check)")
            return (status, 'unverified')
        
        ownership = self._verify_tenant_ownership(pattern, tenant_id)
        
        if ownership is True:
            self._log(f"Found verified and owned match: {pattern}")
            return (status, 'verified')
        elif ownership is False:
            self._log(f"Pattern {pattern} exists but belongs to different tenant")
            return (status, 'unverified')
        else:
            self._log(f"Pattern {pattern} exists but ownership unverified")
            return (status, 'unverified')
    
    def _verify_pattern(self, pattern, domain, timeout=None):
        """Verify if a pattern exists by testing SharePoint URL."""
        self._log(f"Testing pattern: {pattern}")
        
        test_url = self._build_test_url(pattern, domain)
        status = self._check_url(test_url, timeout=timeout or self.DEFAULT_TIMEOUT)
        
        # Log result
        status_messages = {
            self.VERIFIED: f"{pattern} verified",
            self.TIMEOUT: f"{pattern} timeout",
        }
        message = status_messages.get(status, f"{pattern} failed ({status})")
        self._log(message)
        
        return status
    
    def _retry_timeout_patterns(self, patterns, domain, tenant_id=None, timeout=None):
        """Retry patterns that timed out with a longer timeout."""
        timeout = timeout or self.RETRY_TIMEOUT
        self._log(f"No verified match, retrying {len(patterns)} timeout(s) with {timeout}s timeout...")
        
        for pattern in patterns:
            status = self._verify_pattern(pattern, domain, timeout=timeout)
            if status != self.VERIFIED:
                self._log(f"Retry for {pattern}: {status}")
                continue
            
            # Pattern exists - check ownership
            if not tenant_id:
                self._log(f"Retry for {pattern}: exists but no tenant ID")
                return (pattern, self.TIMEOUT)
            
            ownership = self._verify_tenant_ownership(pattern, tenant_id)
            if ownership is True:
                self._log(f"Retry successful - {pattern} verified and owned!")
                return (pattern, self.VERIFIED)
            else:
                self._log(f"Retry for {pattern}: exists but ownership issue")
        
        return None
    
    # SharePoint URL Verification
    
    def _build_test_url(self, pattern, domain):
        """Build SharePoint URL for testing a pattern."""
        hostname = f'{pattern}-my.{self.endpoint}'
        domain_part = domain.replace('.', '_')
        return f'https://{hostname}/personal/test_{domain_part}/_layouts/15/onedrive.aspx'
    
    def _check_url(self, url, timeout=None):
        """Check if a SharePoint URL exists and return status."""
        try:
            r = requests.head(url, timeout=timeout or self.DEFAULT_TIMEOUT, allow_redirects=False)
            # These status codes indicate the tenant exists
            if r.status_code in [403, 404, 401, 302]:
                return self.VERIFIED
            return self.NO_SHAREPOINT
        except requests.exceptions.Timeout:
            return self.TIMEOUT
        except requests.exceptions.ConnectionError as e:
            error_str = str(e).lower()
            if 'name or service not known' in error_str or 'nodename nor servname' in error_str:
                return self.DNS_FAIL
            return self.ERROR
        except Exception:
            return self.ERROR
    
    # Ownership Verification via OpenID
    
    def _verify_tenant_ownership(self, tenant_name, tenant_id):
        """Verify that a tenant name belongs to the given tenant ID using OpenID Configuration.
        
        Args:
            tenant_name: The tenant name to verify (without .onmicrosoft.com)
            tenant_id: The expected tenant ID (GUID)
            
        Returns:
            True if tenant name belongs to tenant ID
            False if tenant name exists but belongs to different tenant
            None if unable to verify (network error, tenant doesn't exist, etc.)
        """
        if not tenant_name or not tenant_id:
            return None
        
        url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/v2.0/.well-known/openid-configuration"
        self._log(f"Verifying tenant ownership via OpenID: {tenant_name} -> {tenant_id}")
        
        try:
            response = requests.get(url, timeout=self.DEFAULT_TIMEOUT)
            if response.status_code != 200:
                return None
            
            extracted_id = self._extract_tenant_id_from_issuer(response.json())
            if extracted_id:
                self._log(f"OpenID issuer tenant ID: {extracted_id}")
                return extracted_id.lower() == tenant_id.lower()
            
            return None
            
        except requests.exceptions.Timeout:
            self._log(f"OpenID verification timeout for {tenant_name}")
            return None
        except Exception as e:
            self._log(f"OpenID verification error for {tenant_name}: {e}")
            return None
    
    def _extract_tenant_id_from_issuer(self, openid_config):
        """Extract tenant ID from OpenID configuration issuer URL.
        
        Args:
            openid_config: OpenID configuration JSON
            
        Returns:
            Tenant ID string or None if not found
        """
        issuer = openid_config.get('issuer', '')
        # Format: https://login.microsoftonline.com/{tenant_id}/v2.0
        if '/v2.0' in issuer:
            parts = issuer.split('/')
            if len(parts) >= 2:
                return parts[-2]
        return None
    
    # Utility Methods
    
    def _log(self, message):
        """Centralized logging for verbose output."""
        if self.verbose:
            print(f"DEBUG: {message}")

def get_tenant_id(domain):
    """Get Tenant ID using Office Apps Live endpoint
    
    Based on AADInternals Get-TenantID function:
    https://github.com/Gerenios/AADInternals/blob/master/AccessToken_utils.ps1
    """
    global verbose
    try:
        url = f"https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={domain}"
        headers = {'User-Agent': 'AutodiscoverClient'}
        
        if verbose:
            print(f"DEBUG: Checking tenant ID for {domain} via Office Apps Live")
        
        response = requests.get(url, headers=headers, timeout=8.0)
        if response.status_code != 200:
            return None
            
        tenant_id = response.json().get('tenantId')
        if tenant_id and verbose:
            print(f"INFO: Found tenant ID for {domain}: {tenant_id}")
        return tenant_id
    except Exception as e:
        if verbose:
            print(f"DEBUG: Failed to get tenant ID for {domain}: {e}")
    return None

def get_tenant_brand_name(domain):
    """Get brand name using GetUserRealm endpoint
    
    Based on AADInternals Get-UserRealmV2 function:
    https://github.com/Gerenios/AADInternals/blob/master/AccessToken_utils.ps1
    """
    global verbose
    try:
        test_user = f"test@{domain}"
        url = f"https://login.microsoftonline.com/GetUserRealm.srf?login={test_user}"
        headers = {'User-Agent': 'AutodiscoverClient'}
        
        if verbose:
            print(f"DEBUG: Getting tenant brand name for {domain} via GetUserRealm")
        
        response = requests.get(url, headers=headers, timeout=8.0)
        if response.status_code != 200:
            return None
            
        brand_name = response.json().get('FederationBrandName')
        if brand_name and verbose:
            print(f"INFO: Found FederationBrandName for {domain}: {brand_name}")
        return brand_name
    except Exception as e:
        if verbose:
            print(f"DEBUG: GetUserRealm failed for {domain}: {e}")
    return None


def lookup_tenant(domain):
    """Discover tenant name using pattern matching."""
    global verbose, endpoint
    
    if verbose:
        print(f"INFO: Attempting tenant discovery for {domain}...")
    
    # Get tenant information upfront
    tenant_id = get_tenant_id(domain)
    brand_name = get_tenant_brand_name(domain)
    
    # If no Azure AD presence, exit early
    if not (tenant_id or brand_name):
        print(f"No Azure AD tenant found for {domain}")
        exit()
    
    # Try to discover the tenant name pattern
    discovery = TenantDiscovery(verbose=verbose, endpoint=endpoint)
    tenant_name, status = discovery.discover_tenant(domain, tenant_id=tenant_id, brand_name=brand_name)
    
    if not tenant_name:
        print(f"\nAzure AD tenant detected but pattern discovery failed")
        if tenant_id:
            print(f"Tenant ID: {tenant_id}")
        if brand_name:
            print(f"Brand Name: {brand_name}")
        print("\nUnable to determine SharePoint URL pattern. Manual verification required.")
        exit()
    
    # Determine method string based on status
    method = "Pattern Matching"
    if status == discovery.TIMEOUT:
        method += " (timeout)"
    elif status == discovery.VERIFIED:
        method += " (verified)"
    
    # Print discovery results
    print(f"\nTenant Discovery Results:\n---------------------")
    if tenant_id:
        print(f"Tenant ID: {tenant_id}")
    print(f"Tenant Name (discovered): {tenant_name}")
    print(f"Discovery Method: {method}")
    print(f"\n{'+'*106}\n")
    
    return tenant_name


# handle ctrl-c with log file
# stole from https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
def signal_handler(sig, frame):
    global exitRequested
    print("\nCTRL-C Detected.")
    # see if this is our first or if we already tried quitting
    # if it's our second time hitting ctrl-c, then close immediately, otherwise wait for graceful
    #print("\nExit status is: {0}\n".format(exitRequested))
    if exitRequested:
        sys.exit(1)
    else:
        #global exitRequested
        exitRequested = True


def test_mysql_connect(mysql_conf):
    config = configparser.ConfigParser()
    if verbose:
        print(f"Config File is at {mysql_conf}")

    #read in our config file
    try:
        config.read(mysql_conf)

        try:
            host = config['mysql']['host']
            database = config['mysql']['database']
            user = config['mysql']['user']
            password = config['mysql']['password']
            port = config['mysql']['port']

            if verbose:
                print(f"Host: {host}:{port}")
                print(f"Database: {database}")
        except:
            print(f"ERROR: Could not get values from the config file")

        # now attempt to connect
        try:
            mydb = mysql.connector.connect(
              host=host,
              user=user,
              password=password,
              database=database
            )
            mydb.autocommit = True
            databaseHelper = mydb.cursor()
            databaseHelper.execute("SELECT VERSION()")
            result = databaseHelper.fetchall()
            mydb.close()
            return result

        except mysql.connector.Error as e:
            print("Error code:", e.errno)        # error number
            print("SQLSTATE value:", e.sqlstate) # SQLSTATE value
            print("Error message:", e.msg)       # error message
            print("Error:", e)                  # errno, sqlstate, msg values
            s = str(e)
            print("Error:", s)                   # errno, sqlstate, msg values
            time.sleep(5)
        except:
            print(f"ERROR: Could not connect to {database} at {host}:{port}. Verify data in config file")
    except:
        print(f"ERROR: Could not read data in config file")



def main():
    global rerun, thread_count, enable_db, killafter, enableKillAfter, verbose, debug

    #set up our ctrl-c checker
    signal.signal(signal.SIGINT, signal_handler)

    # define our variables
    exitRequested = False

    
    # initiate the parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="target domain name (required)", required=True, metavar='')
    parser.add_argument("-t", "--tenant", help="tenant name", metavar='')
    parser.add_argument("-e", "--environment", help="Azure environment to target [commercial (default), chinese, gov]", metavar='')
    parser.add_argument("-u", "--username", help="user to target", metavar='')
    parser.add_argument("-U", "--userfile", help="file containing usernames (wordlists) -- will also take a directory", metavar='')
    parser.add_argument("-p", "--playlist", help="file containing list of paths to user lists (wordlists) to try", metavar='')
    parser.add_argument("-a", "--append", help="mutator: append a number, character, or string to a username", metavar='')
    parser.add_argument("-tr", "--truncate", help="truncate to x characters", metavar='')
    parser.add_argument("-T", "--threads", help="total number of threads (defaut: 100)",default=100, metavar='')
    parser.add_argument("-r", "--rerun", help="force re-run of previously tested tenant/domain/wordlist combination", action='store_true')
    parser.add_argument("-x", "--skip-tried", help="dedupe. skip any usernames from previous runs", action='store_true', default=False)
    parser.add_argument("-n", "--no-db", help="disable logging to db", action='store_true', default=False)
    parser.add_argument("-m", "--mysql", help="file containing mysql data (db.conf)", metavar='')
    parser.add_argument("-o", "--output", help="file to append found users to", metavar='')
    parser.add_argument("-k", "--killafter", help="kill off non-productive jobs after x tries with no success", metavar='')
    parser.add_argument("-v", "--verbose", help="enable verbose output", action='store_true', default=False)
    parser.add_argument("-D", "--debug", help="enable debug output", action='store_true', default=False)

    # read arguments from the command line
    args = parser.parse_args()

    verbose = args.verbose
    debug = args.debug
    appendString = ''
    isUser = False
    isUserFile = False
    isPlaylist = False


    if verbose:
        print("Verbose is ON")

    if debug:
        print("Debug is ON")

    if args.domain:
        target_domain = (args.domain).lower()
        if verbose:
            print("Domain is: %s" % target_domain)
    else:
        target_domain = None

    if args.tenant:
        tenantname = (args.tenant).lower()
        if verbose:
            print("Tenant is: %s" % args.tenant)
    else:
        if verbose:
            print("INFO: No tenant specified. Beginning automatic lookup.")
        tenantname = lookup_tenant(target_domain)


    if args.username:
        print("Checking username: %s" % args.username)
        username = args.username.replace(".","_")
        isUser = True

    if args.userfile:
        if verbose:
            print("Checking file: %s" % args.userfile)
        userfile = args.userfile
        isUserFile = True

    if args.playlist:
        if verbose:
            print(f"Reading in playlist {args.playlist}")
        playlist = args.playlist
        isPlaylist = True


    skip_tried = args.skip_tried
    if verbose:
        print("Skip Tried: {0}".format(skip_tried))

    if args.rerun:
        rerun = True
        skip_tried = False

    if args.truncate:
        truncate = args.truncate
    else:
        truncate = None

    if args.mysql:
        mysql_conf = args.mysql
        try:
            #check to see if file is there
            if os.path.exists(mysql_conf):
                #then check to make sure we can connect
                try:
                    if verbose:
                        print("Testing connection")
                    if (test_mysql_connect(mysql_conf)):
                        print(f"Test connection to mysql db was successful!")
                    else:
                        print(f"Failed to connect to remote server. Please check your settings.")
                        exit()
                except Exception:
                    print(f"ERROR: Could not connect to mysql db")
                    exit()
        except Exception:
            print(f"ERROR: {mysql_conf} does not exist.")
            exit()
    else:
        #mysql_enabled = False
        mysql_conf = None

    if args.no_db:
        enable_db = False
    else:
        enable_db = True

    if verbose:
        print("Enable DB is: {0}".format(enable_db))

    if args.killafter:
        killafter = args.killafter
        enableKillAfter = True

    thread_count = args.threads

    if verbose:
        print("Thread Count: {0}".format(thread_count))

    if args.threads:
        thread_count = args.threads
    else:
        thread_count = 100

    if args.append:
        appendString = args.append.rstrip()
    else:
        appendString = ""

    if args.output:
        output = args.output
    else:
        output = False

    if args.environment:
        environment = args.environment.rstrip()
    else:
        environment = "commercial"

    # set our environment path
    if environment == "commercial":
        environment = "onedrive"
        endpoint = "sharepoint.com"
    if environment == "chinese":
        environment = "onedrive_china"
        endpoint = "sharepoint.cn"
    if environment == "gov":
        environment = "onedrive_gov"
        endpoint = "sharepoint.us"

    #print("Environment is set to {}".format(environment))

    # Here we see what type of input it is: username, userfile, user directory, playlist -- and process accordingly
    if isUser:
        if verbose:
            print("We are checking on a username")
        userdata = username
        try:
            url_checker = UrlChecker(tenantname, target_domain, environment, endpoint, userdata, appendString, skip_tried, mysql_conf, output)
            url_checker.check_user()
        except:
            if verbose:
                print("Error with username")
            pass
        finally:
            del url_checker


    if isUserFile:
        userdata = userfile
        tmp_truncated_users = '/tmp/onedrive_enum.truncated.users'

        #first check for file or folder status
        if os.path.exists(userfile):    #first see if it exists
            if os.path.isfile(userfile):    #then see if it's a file
                try:
                    if truncate:
                        if verbose:
                            print(f"Truncating file.")
                        try:
                            truncate_cut = subprocess.run(['cut',f'-c1-{truncate}',userfile],check=True, capture_output=True)
                        except:
                            print("XCouldn't cut the file")

                        try:
                            if verbose:
                                print("Trying duplicut")
                            f_truncated = open(tmp_truncated_users, "w")

                            try:
                                truncate_results = subprocess.run(['duplicut','-o',tmp_truncated_users],input = truncate_cut.stdout)
                            except:
                                if verbose:
                                    print("No duplicut - trying sort")
                                pass
                            try:
                                truncate_results = subprocess.run(['sort','-u'],input=truncate_cut.stdout,stdout=f_truncated)
                            except:
                                print("well, truncate_results failed")
                            f_truncated.close()
                        except Exception:
                            if verbose:
                                print("Couldn't truncate. Sorry.")
                        
                        userdata = tmp_truncated_users

                    url_checker = UrlChecker(tenantname, target_domain, environment, endpoint, userdata, appendString, skip_tried, mysql_conf, output)
                    if url_checker.tenant_exists:
                        url_checker.check_user_file()
                except Exception as userfileerror:
                    print(userfileerror)
                    if verbose:
                        print("Whoops something happened there with a userfile")
                    pass
                finally:
                    url_checker.sql_export_valid_users()
                    del url_checker
                print("Completed")

            elif os.path.isdir(userfile):   #otherwise if it's a dir
                if verbose:
                    print(f"Reading in directory: {userfile}")
                file_list = os.listdir(userfile)
                i = 0
                for currentfile in sorted(file_list):
                    i+=1
                    try:
                        safe_file_name = currentfile.rstrip()   #take out any newlines that might exist
                        # see if our path ends in a '/'
                        if userdata.endswith('/'):
                            slash = ""
                        else:
                            slash = "/"
                        #now add back in the original path so we have our full file path
                        safe_file_name = f'{userdata}{slash}{safe_file_name}'
                        print(f"Running with user list {i} of {len(file_list)} : {safe_file_name}")
                        url_checker = UrlChecker(tenantname, target_domain, environment, endpoint, safe_file_name, appendString, skip_tried, mysql_conf, output)
                        if url_checker.tenant_exists:
                            url_checker.check_user_file()
                    except:
                        if verbose:
                            print("Whoops - had an issue there with a file from the directory.")
                        pass
                    finally:
                        url_checker.sql_export_valid_users()
                        del url_checker
                print("Completed")


        else:
            print(f"ERROR: {userfile} does not exist.")
            exit()

    if isPlaylist:
        #read in our playlist
        if os.path.exists(playlist):
            if os.path.isfile(playlist):
                with open(playlist, 'r') as currentlist:
                    total_lines = len(currentlist.readlines())
                    if verbose:
                        print(f"Total lines: {total_lines}")
                    currentlist.seek(0) # return to the beginning of our file now that we have count
                    i=0
                    for currentfile in currentlist:
                        i+=1
                        safe_file_name = currentfile.rstrip()
                        print(f"Running with user list {i} of {total_lines}: {currentfile}")
                        try:
                            url_checker = UrlChecker(tenantname, target_domain, environment, endpoint, safe_file_name, appendString, skip_tried, mysql_conf, output)
                            if url_checker.tenant_exists:
                                url_checker.check_user_file()
                        except:
                            if verbose:
                                print("Whoops - had an issue there")
                            pass
                        finally:
                            del url_checker
                    print("Completed.")
                    url_checker.sql_export_valid_users()

        else:
            print(f"ERROR: {playlist} does not exist.")
            exit()

if __name__ == "__main__":
    main()
