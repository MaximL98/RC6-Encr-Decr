import sqlite3
from sqlite3 import Error, Connection
import hashlib

import utils

# Function to create a database connection
def create_connection(db_file="users_data.db") -> Connection:
    """Creates a database connection to the SQLite database specified by db_file.
    Args:
        db_file (str, optional): The name of the database file. Defaults to "users_data.db".

    Returns:
        Connection: The Connection object, or None if an error occurs.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)

    return conn

# Function to create the user_data table
def create_table(conn):
    """Creates the user_data table with columns for personal and card information."""

    user_data_table = """ CREATE TABLE user_data (
                First_Name CHAR(25) NOT NULL,
                Last_Name CHAR(25),
                Passcode TEXT,
                Card_Number INT PRIMARY KEY,
                Date CHAR(25),
                CVC INT,
                UNIQUE(Passcode, Card_Number)
            ); """

    cur = conn.cursor()
    cur.execute(user_data_table)

# Function to insert data into the table
def insert_data(conn, data):
    """Inserts multiple rows of data into the user_data table using a prepared statement."""

    sql = """ INSERT INTO user_data (First_Name, Last_Name, Passcode, Card_Number, Date, CVC)
                VALUES (?,?,?,?,?,?)"""

    cur = conn.cursor()
    for person in data:
        cur.execute(sql, person)
    conn.commit()


# Function to update passcode for a specific card number
def update_data(conn, card_number, hashed_pass):
    """Updates the Passcode for the given card_number in the user_data table."""

    sql = """ UPDATE user_data
              SET Passcode = ?
              WHERE card_number = ? """

    cur = conn.cursor()
    cur.execute(sql, (hashed_pass, card_number))
    conn.commit()

# Function to delete rows within a specified range
def delete_rows_range(conn, start, end):
    """Deletes rows from the user_data table where the rowid is between start and end."""

    sql = "DELETE FROM user_data WHERE rowid BETWEEN ? AND ?"

    cur = conn.cursor()
    cur.execute(sql, (start, end))
    conn.commit()

# Function to retrieve passcode for a specific card number
def select_passcode(conn, card_number):
    """Retrieves the Passcode from the user_data table for the given card_number."""

    sql = "SELECT Passcode FROM user_data WHERE Card_Number = ?"

    cur = conn.cursor()
    cur.execute(sql, (card_number,))
    passcode = cur.fetchone()  # Fetch the first row
    return passcode[0] if passcode else None

def check_exist():
    sql =  """SELECT EXISTS(
    SELECT 1 FROM user_data
    WHERE First_Name = ?
    AND Last_Name = ?
    AND Card_Number = ?
    ) AS UserExists;"""

    first_name, last_name, card_num = utils.get_user_info()

    conn = create_connection()
    cur = conn.cursor()
    cur.execute(sql, (first_name, last_name, card_num,))
    result = cur.fetchone()
    conn.close()
    return result[0], first_name, last_name

def check_cred(first_name, last_name):
    sql =  """SELECT EXISTS(
    SELECT 1 FROM user_data
    WHERE Passcode = ?
    AND CVC = ?
    AND Date = ?
    ) AS UserExists;"""

    passcode, cvc, data = utils.get_cred(first_name, last_name)
    hashed_pass = hash_func(passcode)
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(sql, (hashed_pass, cvc, data,))
    result = cur.fetchone()
    conn.close()
    return result[0]

# Function to hash a passcode using SHA-256
def hash_func(passcode):
    """Hashes the provided passcode using the SHA-256 algorithm."""
    return hashlib.sha256(str(passcode).encode()).digest()

# Main execution block
def main():
    # Establish database connection
    conn = create_connection()

    # cur = conn.cursor()
    #cur.execute("DROP TABLE IF EXISTS user_data")
    #create_table(conn)

    # Sample data
    people_data = [
    ("John", "Smith", hash_func(1234), 987654321, "05/25", 456),
    ("Emily", "Johnson", hash_func(5678), 123456789, "08/27", 789),
    ("Michael", "Williams", hash_func(2468), 456789123, "11/23", 321),
    ("Sarah", "Brown", hash_func(1357), 789123456, "02/30", 654),
    ("David", "Jones", hash_func(9876), 321654987, "04/28", 987),
    ("Jessica", "Davis", hash_func(6543), 654987321, "09/22", 123),
    ("Christopher", "Miller", hash_func(7890), 147258369, "06/26", 456),
    ("Amanda", "Wilson", hash_func(3456), 369147258, "12/18", 789),
    ("Matthew", "Taylor", hash_func(2345), 852963741, "10/31", 321),
    ("Lauren", "Anderson", hash_func(5432), 963852741, "03/29", 654)]

    testing_data = [("c1", "c1", hash_func(1111), 1, "1/1", 111)]

    #insert_data(conn, people_data)

    # Retrieve passcode for a specific card number
    passcode = select_passcode(conn, 987654321)
    print(passcode == hash_func(1234))
    #delete_rows_range(conn, 10, 20)

    # Close the database connection
    conn.close()

if __name__ == '__main__':
    main()
