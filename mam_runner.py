import subprocess
import time
path = "./mam.c/bazel-bin/mam/examples/send-msg"

host = "node1.puyuma.org"
port = "14265"
seed = "TFKQZVPZVWLXBJGNEPPVZNZYJFFPDMEQGGDPGSRMNXAURIELGLUCSSPGDGEQQFANGOWVXPUHNIDOZ9999"
payload = ""
last_packet = "yes"

time_list = []
for i in range(50, 2000, 50):
    for j in range(i):
        payload = payload + "a"

    start = time.time()
    command = f"{path} {host} {port} {seed} {payload} {last_packet}"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    curl_response = str(out.decode('ascii'))
    # print(curl_response)
    curl_response = str(err.decode('ascii'))
    # print(curl_response)
    end = time.time()
    time_list.append((end - start)*(10**6)) # Times 10^6 to convert sec to microsecond (us)

print(time_list)