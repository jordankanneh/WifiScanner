using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using SharpPcap.LibPcap;


namespace WifiScanner
{
    internal class Program
    {    
        
    static void Main(string[] args)
        {
            // Find available network interfaces
            var devices = CaptureDeviceList.Instance; //Instance Property 

            if (devices.Count < 1)
            {
                Console.WriteLine("No network interfaces found.");
                return;
            }

            Console.WriteLine("Available network interfaces:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i + 1}. {devices[i].Description}");
            }

            Console.Write("Select an interface (1-" + devices.Count + "): ");
            int selectedDeviceIndex = int.Parse(Console.ReadLine()) - 1;

            if (selectedDeviceIndex < 0 || selectedDeviceIndex >= devices.Count)
            {
                Console.WriteLine("Invalid selection.");
                return;
            }

            ICaptureDevice device = devices[selectedDeviceIndex];
            device.OnPacketArrival += new PacketArrivalEventHandler(PacketHandler);
            string filter = "icmp or udp port 53";
            // Open the device for capturing
            device.Open(DeviceModes.Promiscuous);
            device.Filter = filter;
            
            // Start capturing packets
            device.StartCapture();

            Console.WriteLine("Capturing network traffic. Press any key to stop..");
            Console.ReadKey();

            // Stop capturing and close the device
            device.StopCapture();
            device.Close();
        }

        private static void PacketHandler(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var time = rawPacket.Timeval.Date;
            var len = rawPacket.Data.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
                time.Hour, time.Minute, time.Second, time.Millisecond, len);
            var p = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            Console.WriteLine(p.ToString());
       
        
        }

    } 
}