import logging
import subprocess
import threading
import time
import os
import psutil
import pandas as pd

logs = []

def stress_test(script, count, delay=0):
    try:
        for i in range(count):
            time.sleep(delay)

            start_time = round(time.time(), 2)  # start time

            process = subprocess.Popen(['python', './' + script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            end_time = round(time.time(), 2)  # end time

            # execution time
            exec_time = round(end_time - start_time, 2)


            logs.append({
                'Script': script,
                'Thread': i+1,
                'Execution Time (s)': exec_time
            })

    except Exception as e:
        print(f'Error in stress_test for script {script}: {e}')


threading.Thread.stop_request = threading.Event()

scripts = [('registry.py', 1, 0), ('peer.py', 1000, 5)]  # Added delay for peer.py
threads = []

try:
    for script, count, delay in scripts:
        thread = threading.Thread(target=stress_test, args=(script, count, delay))
        threads.append(thread)

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

except KeyboardInterrupt:
    # Set the stop_request flag in case of a KeyboardInterrupt
    for thread in threads:
        thread.stop_request.set()
    # Wait for all threads to finish after setting the stop_request flag
    for thread in threads:
        thread.join()
finally:

    del threading.Thread.stop_request

    # Convert the logs list to a DataFrame
    logs_df = pd.DataFrame(logs)

    # Save the logs DataFrame to an Excel file
    logs_df.to_excel('stress_test.xlsx', index=False)