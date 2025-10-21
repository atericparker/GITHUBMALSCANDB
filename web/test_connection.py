#!/usr/bin/env python3
"""
Quick test script to verify database connection and schema
"""
import os
import sys
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras

# Load environment variables
load_dotenv()

def test_connection():
    """Test database connection and verify tables exist"""
    print("Testing TimescaleDB connection...")
    print("-" * 50)

    try:
        # Connect to database
        conn = psycopg2.connect(
            dbname=os.getenv('POSTGRES_DATABASE'),
            user=os.getenv('POSTGRES_USERNAME'),
            password=os.getenv('POSTGRES_PASSWORD'),
            host=os.getenv('POSTGRES_HOSTNAME'),
            port=os.getenv('POSTGRES_PORT'),
            sslmode='require'
        )
        print("✓ Database connection successful!")

        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Check for required tables
        tables = ['repositories', 'repo_log', 'scan_log']
        print("\nChecking for required tables...")

        for table in tables:
            cur.execute(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = %s
                );
            """, (table,))
            exists = cur.fetchone()['exists']
            if exists:
                cur.execute(f"SELECT COUNT(*) as count FROM {table}")
                count = cur.fetchone()['count']
                print(f"  ✓ {table}: {count} rows")
            else:
                print(f"  ✗ {table}: NOT FOUND")
                return False

        # Get some sample statistics
        print("\nDatabase Statistics:")

        cur.execute("SELECT COUNT(DISTINCT repo_id) as count FROM repositories")
        repo_count = cur.fetchone()['count']
        print(f"  Total Repositories: {repo_count}")

        cur.execute("SELECT COUNT(*) as count FROM scan_log")
        scan_count = cur.fetchone()['count']
        print(f"  Total Scans: {scan_count}")

        cur.execute("""
            SELECT outcome, COUNT(*) as count
            FROM scan_log
            GROUP BY outcome
            ORDER BY count DESC
        """)
        outcomes = cur.fetchall()
        print("\n  Scans by Outcome:")
        for outcome in outcomes:
            print(f"    {outcome['outcome']}: {outcome['count']}")

        cur.close()
        conn.close()

        print("\n" + "-" * 50)
        print("✓ All tests passed! Database is ready.")
        return True

    except psycopg2.Error as e:
        print(f"\n✗ Database error: {e}")
        return False
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return False

if __name__ == '__main__':
    success = test_connection()
    sys.exit(0 if success else 1)
