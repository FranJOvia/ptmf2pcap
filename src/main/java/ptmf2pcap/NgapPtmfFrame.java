package ptmf2pcap;
import java.net.InetAddress;

/**
 * NgapPtmfFrame object represents a PTMF frame of NGAP type
 *
 * The frames of this type do not contain an Ethernet packet with all the upper layers,
 * but contains just the NGAP layer. Thus:
 *    - The transport protocol is assumed to be SCTP with port 38412 and hardcoded IP addresses 0.0.0.1 and 0.0.0.2
 *    - MAC addresses, checksums and so on are filled with default values (typically zeroes)
 */
public class NgapPtmfFrame extends PtmfFrame {

	/*
	 * NgapPtmfFrame constants
	 */
	public static final int FRAME_HEADER_LENGTH = 72+4;
	private static final int SRCIP_OFFSET = 10;
	private static final int DSTIP_OFFSET = 14;
	private static final int SRCPORT_OFFSET = 0;
	private static final int DSTPORT_OFFSET = 0;
	//
	private static final byte[] AMF_IPV4_BYTES = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
	private static final byte[] GNB_IPV4_BYTES = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02};

	/**
	 * Returns a NgapPtmfFrame object
	 *
	 * @return	The NgapPtmfFrame object
	 */
	public NgapPtmfFrame() {
		super();
	};

	/**
	 * Returns a NgapPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @return	The NgapPtmfFrame object
	 */
	public NgapPtmfFrame(byte[] byteContent) {
		super(byteContent);
	};

	/**
	 * Returns a NgapPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @param	order	the relative order of the frame
	 * @return	The NgapPtmfFrame object
	 */
	public NgapPtmfFrame(byte[] byteContent, int order) {
		super(byteContent, order);
	};

	/**
	 * Returns the frame in an IPv4 packet
	 * The transport layer is assumed to be SCTP
	 *
	 * @return	The IPv4 packet
	 */
	public byte[] getIpv4Packet() {
		byte[] sctpPacket = null;
		byte[] ipv4Packet = null;
		InetAddress amfIp, gnbIp;
		bool toAmf = true; //TODO: find position of this flag
		//TODO: change ip depending on direction...
		try {
			amfIp = InetAddress.getByAddress(AMF_IPV4_BYTES);
		} catch(Exception e) {
			/*
			 * This should never happen since the argument we are passing to
			 * InetAddress.getByAddress is a constant whose value is correct,
			 * but we need to provide try-catch anyway
			 */
			System.out.println("Exception when creating amfIp!!");
			amfIp = null;
		};
		try {
			gnbIp = InetAddress.getByAddress(GNB_IPV4_BYTES);
		} catch(Exception e) {
			/*
			 * This should never happen since the argument we are passing to
			 * InetAddress.getByAddress is a constant whose value is correct,
			 * but we need to provide try-catch anyway
			 */
			System.out.println("Exception when creating gnbIp!!");
			gnbIp = null;
		};
		if (toAmf){
			sctpPacket = Pcap.createSctpPacket(38412, 38412, this.getBody(), gnbIp, amfIp);
			ipv4Packet = Pcap.createIpv4Packet(gnbIp, amfIp, Pcap.IP_PROTOCOL_SCTP, sctpPacket);
		}else{
			sctpPacket = Pcap.createSctpPacket(38412, 38412, this.getBody(), amfIp, gnbIp);
			ipv4Packet = Pcap.createIpv4Packet(amfIp, gnbIp, Pcap.IP_PROTOCOL_SCTP, sctpPacket);
		}
		return ipv4Packet;
	};

	/*
	 * Member methods to access the static constants that are
	 * defined/overriden at this class
	 */
	public int GET_FRAME_HEADER_LENGTH() {
		return FRAME_HEADER_LENGTH;
	};
	public int GET_SRCIP_OFFSET() {
		return SRCIP_OFFSET;
	};
	public int GET_DSTIP_OFFSET() {
		return DSTIP_OFFSET;
	};
	public int GET_SRCPORT_OFFSET() {
		return SRCPORT_OFFSET;
	};
	public int GET_DSTPORT_OFFSET() {
		return DSTPORT_OFFSET;
	};

};