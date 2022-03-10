from devices import CiscoNetworkDevice, HuaweiNetworkDevice
# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def convert():
    cisco = CiscoNetworkDevice()
    cisco.ParseConfigFromFile(file_name="configs/m.txt")
    huawei = HuaweiNetworkDevice()
    huawei.ACLs = cisco.ACLs
    huawei.ObjectGroups = cisco.ObjectGroups
    for line in huawei.GenerateAcl():
        print(line)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    convert()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
