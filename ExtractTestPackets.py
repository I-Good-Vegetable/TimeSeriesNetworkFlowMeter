from pyshark import FileCapture


def main():
    filepath = 'E:/NetworkIntrusionDatasets/CICIDS2017/PCAPs/Thursday-WorkingHours.pcap'
    outputFile = 'Data/PCAP/Test.pcap'
    fileCapture = FileCapture(filepath, output_file=outputFile)
    fileCapture.load_packets(10000)
    pass


if __name__ == '__main__':
    main()
