{
	onEnter: function (log, args, state) {
		var sockfd = args[0].toInt32();
		var dest_addr = args[1];
		var sin_family = Memory.readU8(dest_addr.add(1));
		if (sin_family == 1) {
			log("connect sockfd=" + sockfd + ",family=" + sin_family + ",path=" + dest_addr.add(2).readUtf8String());
		} else if (sin_family == 2) {
			var sin_port = Memory.readU16(dest_addr.add(2));
			var sin_port = ((sin_port & 0xff) << 8) | ((sin_port >> 8) & 0xff);
			var sin_addr = Memory.readU32(dest_addr.add(4));
			var sin_ip = (sin_addr & 0xff).toString() + '.' + ((sin_addr >> 8) & 0xff).toString() +
				'.' + ((sin_addr >> 16) & 0xff).toString() + '.' + ((sin_addr >> 24) & 0xff).toString();
			log("connect sockfd=" + sockfd + ",family=" + sin_family + ",ip=" + sin_ip + ",port=" + sin_port);
		} else {
			log("connect sockfd=" + sockfd + ",family=" + sin_family);
		}
	},
	onLeave: function (log, retval, state) {
		log('->' + retval)
	}
}
