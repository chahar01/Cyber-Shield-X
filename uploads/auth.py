failed = {}
with open("auth.log","r") as file:
    count = 0
    for line in file:
        if "Failed password" in line and "from" in line:
            count += 1
            ip_list = line.split()
            if "from" in ip_list:
                ip = ip_list[ip_list.index("from") + 1]
                failed[ip] = failed.get(ip,0) +1

print("**********BRUTEFORCEDETECTION**********")
print("---------------------------------------")

for ip, attempts in failed.items():
    if attempts >= 5:
        print("Brute Force detected from the IP: ",ip)
print("Total failed attempts",count)