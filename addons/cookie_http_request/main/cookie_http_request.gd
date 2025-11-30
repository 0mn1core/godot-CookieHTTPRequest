# Extension of the HTTPRequest node to automatically handle processing 'Set-Cookie' headers and adding cookies to future requests
#
# Provides a partial implementation of the RFC-6265bis specification for processing the 'Set-Cookie'
# header from HTTP responses, and stores the cookies in an autoloaded cookie store. On outgoing
# requests, will pull the appropriate cookies from the store to attach to the request, with the
# cookies on a provided `Cookies` header taking precedence.
#
# Specification: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-15
class_name CookieHTTPRequest
extends HTTPRequest


# Mapping of HTTP Date months to their month values
const HTTP_DATE_MONTH_MAP := {
	"Jan": 1,
	"Feb": 2,
	"Mar": 3,
	"Apr": 4,
	"May": 5,
	"Jun": 6,
	"Jul": 7,
	"Aug": 8,
	"Sep": 9,
	"Oct": 10,
	"Nov": 11,
	"Dec": 12
}
# Sum of cookie name and value can't be more than 4096 octets
const NAME_VALUE_SUM_LIMIT := 4096
# Attribute values can't be more than 1024 octets
const ATTR_VALUE_LIMIT := 1024
# Cookie expiry time can't be greater than 400 days
const MAXIMUM_COOKIE_DELTA := 34560000


var CONTROL_CHARACTER_EXCEPT_TAB_MATCHER := RegEx.new()


# Signal doesn't pass any request information to listeners, have to do go with brittle approach of saving off URL
var _current_request_url


func _ready():
	# Compile regex with its search pattern 
	CONTROL_CHARACTER_EXCEPT_TAB_MATCHER.compile("[^\\t\\P{C}]")
	# Connect the set cookie header processor to the request completed signal
	self.request_completed.connect(_process_set_cookie_headers)


# Override for `HTTPRequest` `request` method, attaches relevant cookies from cookie store and handles data and blocking for processing set_cookies
func cookie_request(url: String, custom_headers:= PackedStringArray(), method:= HTTPClient.Method.METHOD_GET, request_data:= "") -> Error:
	print("in override function")
	# Check if _current_request_url is set, means it's still processing last request
	if (_current_request_url != null):
		return ERR_BUSY
	var cookie_store_header = HTTPCookieStore.get_cookie_header_for_request(url)
	var augmented_headers = custom_headers
	if (cookie_store_header != null):
		augmented_headers.push_back(cookie_store_header)
	var error = request(url, augmented_headers, method, request_data)
	# Save off URL for cookie processing
	if (error == OK):
		_current_request_url = url
	return error


# Override for `HTTPRequest` `request_raw` method, attaches relevant cookies from cookie store and handles data and blocking for processing set_cookies
func cookie_request_raw(url: String, custom_headers:= PackedStringArray(), method:= HTTPClient.Method.METHOD_GET, request_data_raw:= PackedByteArray()) -> Error:
	# Check if _current_request_url is set, means it's still processing last request
	if (_current_request_url != null):
		return ERR_BUSY
	var cookie_store_header = HTTPCookieStore.get_cookie_header_for_request(url)
	var augmented_headers = custom_headers
	if (cookie_store_header != null):
		augmented_headers.push_back(cookie_store_header)
	var error = request_raw(url, augmented_headers, method, request_data_raw)
	# Save off URL for cookie processing
	if (error == OK):
		_current_request_url = url
	return error


# Signal responder for requests. Grabs the `set_cookie` headers, process them, then sends them to the cookie store
func _process_set_cookie_headers(result, _response_code, headers: PackedStringArray, _body) -> void:
	if (result != HTTPRequest.Result.RESULT_SUCCESS):
		# Not going to print a debug for every failed request
		_current_request_url = null
		return
	if (_current_request_url == null):
		CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Request", "Request URL wasn't saved, skipping cookie processing")
		return
	# HTTP cares not for floating point precision
	var process_time := int(roundf(Time.get_unix_time_from_system()))
	var set_cookie_header_strings := _get_set_cookie_headers(headers)
	# Map
	var cookie_dicts = []
	for i in range(set_cookie_header_strings.size()):
		var processed_cookie_header = _verify_and_parse_set_cookie_header(set_cookie_header_strings[i], process_time)
		if (processed_cookie_header == null):
			continue
		var cookie = _finalize_storage_cookie(processed_cookie_header, process_time)
		if (cookie == null):
			continue
		cookie_dicts.append(cookie)
	HTTPCookieStore.store_cookies(cookie_dicts, _current_request_url)
	# Null out current_request_url
	_current_request_url = null


# Get all `set-cookie` headers from an array of headers.
func _get_set_cookie_headers(headers: PackedStringArray) -> PackedStringArray:
	var set_cookie_headers: PackedStringArray = [];
	for header in headers:
		if(header.strip_edges().to_lower().begins_with("set-cookie")):
			set_cookie_headers.append(header)
	return set_cookie_headers


# Parse `set_cookie` headers into cookie dictionaries.
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _verify_and_parse_set_cookie_header(header: String, process_time: int):
	# If a set cookie header contains any control characters except tab, discard it.
	var trimmed_header = header.trim_prefix("Set-Cookie: ")
	if (CONTROL_CHARACTER_EXCEPT_TAB_MATCHER.search(trimmed_header) != null):
		return null
	var set_cookie_parts := trimmed_header.split(";")
	# Filter
	for i in range(set_cookie_parts.size() - 1, -1, -1):
		if (set_cookie_parts[i].strip_edges().is_empty()):
			set_cookie_parts.remove_at(i)
	# `Set-Cookie` begins with name-value pair.
	var cookie = _verify_and_parse_set_cookie_name_value(set_cookie_parts[0])
	if (cookie == null):
		return null
	set_cookie_parts.remove_at(0)
	cookie.attributes = {}
	cookie.creation_time = process_time
	cookie.last_access_time = process_time 
	# Parse rest of `Set-Cookie`.
	for part in set_cookie_parts:
		var attribute_array = part.split("=")
		var attribute_name = attribute_array[0].strip_edges().to_lower()
		attribute_array.remove_at(0)
		# Join back on `=` in case the value had an equal symbol in it.
		var attribute_value = "=".join(attribute_array).strip_edges()
		match attribute_name:
			"expires":
				var parsed_expires_value = _verify_and_parse_expire(attribute_value, process_time)
				if (parsed_expires_value != null):
					cookie.attributes.Expires = parsed_expires_value
			"max-age":
				var parsed_max_age_value = _verify_and_parse_max_age(attribute_value, process_time)
				if (parsed_max_age_value != null):
					cookie.attributes.Max_Age = parsed_max_age_value
			"domain":
				var parsed_domain = _verify_and_parse_domain(attribute_value)
				if (parsed_domain != null):
					cookie.attributes.Domain = _verify_and_parse_domain(attribute_value)
			"path":
				var parsed_path = _verify_and_parse_path(attribute_value)
				if (parsed_path != null):
					cookie.attributes.Path = _verify_and_parse_path(attribute_value)
			"secure":
				cookie.attributes.Secure = null
			"httponly":
				cookie.attributes.HttpOnly = null
			"samesite":
				cookie.attributes.SameSite = _verify_and_parse_same_site(attribute_value)
	return cookie


# Parse the <name>=<value> portion of a `Set-Cookie` header
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _verify_and_parse_set_cookie_name_value(name_value_pair: String):
	var name_value_dictionary = {}
	var name_value_array := name_value_pair.split("=")
	if (name_value_array.size() == 1):
		name_value_dictionary.name = ""
		name_value_dictionary.value = name_value_pair.strip_edges()
	else:
		name_value_dictionary.name = name_value_array[0].strip_edges()
		name_value_array.remove_at(0)
		# Join back on `=` in case the value had an equal symbol in it.
		name_value_dictionary.value = "=".join(name_value_array).strip_edges()
	# Check values
	if (name_value_dictionary.name.is_empty() and name_value_dictionary.value.is_empty()):
		CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Name-Value", "Cookie name and value are empty, discarding cookie")
		return null
	# Check size
	if ((name_value_dictionary.name.to_utf8_buffer().size() + name_value_dictionary.value.to_utf8_buffer().size()) > NAME_VALUE_SUM_LIMIT):
		CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Name-Value", "Sum of name and value greater than 4096 octets, discarding cookie")
		return null
	return name_value_dictionary


# Parses the `Expire` `HTTP-date` string attribute value.
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _verify_and_parse_expire(http_date: String, process_time: int):
	# HTTP-date format:
	# <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
	var datetime_dict := {}
	# Strip <day-name> string if present. If not, the algorithm specified by the RFC doesn't care.
	var stripped_dayname_string = http_date.get_slice(",", 1).strip_edges()
	var space_split_array = stripped_dayname_string.split(" ")
	# Make sure that at least the day, month, year, and HH:MM:SS string are present.
	if (space_split_array.size() < 4):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "HTTP Date is malformed, discarding attribute")
		return null
	var day_of_month = space_split_array[0]
	if (!day_of_month.is_valid_int()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "day-of-month is not an integer, discarding attribute")
		return null
	datetime_dict.day = int(day_of_month)
	var month = HTTP_DATE_MONTH_MAP[space_split_array[1]]
	if (month == null):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "month is not a valid value, discarding attribute")
		return null
	datetime_dict.month = month
	var year = space_split_array[2]
	if (!year.is_valid_int()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "year is not an integer, discarding attribute")
		return null
	year = int(year)
	# In 2024, no one is sending 2 digit years. But I do what the algorithm commands.
	if (year >= 70 and year <= 99):
		year += 1900
	elif (year >= 0 and year <= 69):
		year += 2000
	datetime_dict.year = year
	var colon_split_array = space_split_array[3].split(":")
	if (colon_split_array.size() != 3):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "hms-time is malformed, discarding attribute")
		return null
	var hour = colon_split_array[0]
	if (!hour.is_valid_int()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "hour is not an integer, discarding attribute")
		return null
	datetime_dict.hour = int(hour)
	var minute = colon_split_array[1]
	if (!minute.is_valid_int()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "minute is not an integer, discarding attribute")
		return null
	datetime_dict.minute = int(minute)
	var second = colon_split_array[2]
	if (!second.is_valid_int()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "second is not an integer, discarding attribute")
		return null
	datetime_dict.second = int(second)
	# Final algorithm compliance checks
	if (datetime_dict.day < 1 or datetime_dict.day > 31):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "day-of-month is not in allowed range, discarding attribute")
		return null
	if (datetime_dict.year < 1601):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "year is not in allowed range, discarding attribute")
		return null
	if (datetime_dict.hour < 0 or datetime_dict.hour > 23):
		print(datetime_dict.hour)
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "hour is not in allowed range, discarding attribute")
		return null
	if (datetime_dict.minute < 0 or datetime_dict.minute > 59):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "minute is not in allowed range, discarding attribute")
		return null
	if (datetime_dict.second < 0 or datetime_dict.second > 59):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Expires", "second is not in allowed range, discarding attribute")
		return null
	# HTTP cares not for floating point precision
	var expiry_time = int(roundf(Time.get_unix_time_from_datetime_dict(datetime_dict)))
	var cookie_age_limit = process_time + MAXIMUM_COOKIE_DELTA
	return min(expiry_time, cookie_age_limit)


# Parses the `Max-Age` string attribute value
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _verify_and_parse_max_age(max_age: String, process_time: int):
	if (max_age.is_empty()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Max-Age", "value is empty, discarding attribute")
		return null
	if (max_age[0] == "+" or !max_age.is_valid_int()):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Max-Age", "value is malformed, discarding attribute")
		return null
	var delta_seconds = min(int(max_age), MAXIMUM_COOKIE_DELTA)
	if (delta_seconds <= 0):
		# I'm not figuring out the earliest representable time in Godot, I'm just setting it to epoch.
		return 0
	return process_time + delta_seconds


# Parses the `Domain` string attribute value
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _verify_and_parse_domain(domain: String):
	var cookie_domain = domain.trim_prefix('.').to_lower()
	# Check size
	if (cookie_domain.to_utf8_buffer().size() > ATTR_VALUE_LIMIT):
		CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Domain", "Attribute value greater than 1024 octets, discarding attribute")
		return null
	return cookie_domain


# Parse the `Path` string attribute value
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _verify_and_parse_path(path: String):
	if (path.is_empty() or path[0] != "/"):
		return _get_cookie_default_path(_current_request_url)
	else:
		if (path.to_utf8_buffer().size() > ATTR_VALUE_LIMIT):
			CookieDebug.push_debug(CookieDebug.LEVEL.WARN, "Path", "Attribute value greater than 1024 octets, discarding attribute")
			return null
		return path


# Parses the `SameSite` string attribute value
func _verify_and_parse_same_site(same_site: String) -> String:
	match same_site.to_lower():
		"none":
			return "None"
		"strict":
			return "Strict"
		"lax":
			return "Lax"
		_:
			return "Default"


# Finalizes the storage cookie using the processed set_cookie header
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _finalize_storage_cookie(processed_cookie: Dictionary, process_time: int):
	var storage_cookie = processed_cookie;
	var expiry_time = _get_finalized_expiry_time(storage_cookie)
	if (expiry_time != null):
		storage_cookie.expiry_time = expiry_time
		storage_cookie.persistent_flag = true
	else:
		storage_cookie.expiry_time = HTTPUtils.MAX_SECONDS
		storage_cookie.persistent_flag = false
	var domain_attributes = _get_finalized_domain(storage_cookie)
	if (domain_attributes == null):
		return null
	storage_cookie.domain = domain_attributes.domain
	storage_cookie.host_only_flag = domain_attributes.host_only_flag
	storage_cookie.path = _get_finalized_path(storage_cookie)
	storage_cookie.secure_only_flag = storage_cookie.attributes.has("Secure")
	if (storage_cookie.secure_only_flag and !HTTPUtils.is_request_secure(_current_request_url)):
		CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Can't store a 'Secure` cookie from an unsecure request, discarding cookie")
		return null
	# Doesn't really matter for purpose of this, I can't stop someone from altering the code to look at cookies.
	storage_cookie.http_only_flag = storage_cookie.attributes.has("HttpOnly")
	# TODO: If http only flag was set and request was made from a "Non-HTTP API" should discard. Does that just mean cookie that's manually added by program rather than request?
	storage_cookie.same_site_flag = storage_cookie.attributes.SameSite if storage_cookie.attributes.has("SameSite") else "Default"
	if (storage_cookie.same_site_flag == "None" and !storage_cookie.secure_only_flag):
		CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "SameSite can't be 'None' without 'Secure' attribute, discarding cookie")
		return null
	if (storage_cookie.name.to_lower().begins_with("__secure-") and !storage_cookie.secure_only_flag):
		CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Cookie name prefixed with '__secure-' but no `Secure` attribute, discarding cookie")
		return null
	if (storage_cookie.name.to_lower().begins_with("__host-")):
		if (!storage_cookie.secure_only_flag):
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Cookie name prefixed with '__host-' but no `Secure` attribute, discarding cookie")
			return null
		if (!storage_cookie.host_only_flag):
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Cookie name prefixed with '__host-' but domain attribute provided, discarding cookie")
			return null
		if (storage_cookie.path != "/"):
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Cookie name prefixed with '__host-' but path is not '/', discarding cookie")
			return null
	if (storage_cookie.name.is_empty()):
		if (storage_cookie.value.to_lower().begins_with("__secure-")):
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Cookie name empty and value prefixed with '__secure-', discarding cookie")
			return null
		if (storage_cookie.value.to_lower().begins_with("__host-")):
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Storage", "Cookie name empty and value prefixed with '__host-', discarding cookie")
			return null
	storage_cookie.erase("attributes")
	return storage_cookie;


# Gets the finalized expiry time for a cookie based off processed attributes. `Max-Age` has precedence over expires
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _get_finalized_expiry_time(cookie: Dictionary):
	# `Max-Age` has precedence over `Expires`.
	if (cookie.attributes.has("Max_Age")):
		return cookie.attributes.Max_Age
	if (cookie.attributes.has("Expires")):
		return cookie.attributes.Expires
	return null


# Gets the finalized domain for a storage cookie, or null if it should be discarded entirely
# No return type since GDscript doesn't have nullable types yet: https://github.com/godotengine/godot-proposals/issues/162
func _get_finalized_domain(cookie: Dictionary):
	# TODO: Algorithm says to work with canonicalized hostnames, but I have no idea how to make DNS requests to get CNAME records.
	var domain_return = {}
	var domain_attribute= ""
	if (cookie.attributes.has("Domain")):
		domain_attribute = cookie.attributes.Domain
	if (!domain_attribute.is_empty()):
		if (domain_attribute.to_ascii_buffer().get_string_from_ascii() != domain_attribute):
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Domain", "Finalized domain attribute not in ASCII, discarding cookie")
			return null
		if (!HTTPUtils.domain_match(HTTPUtils.get_url_domain(_current_request_url), domain_attribute)):
			print("Debugging")
			print(_current_request_url)
			print(domain_attribute)
			CookieDebug.push_debug(CookieDebug.LEVEL.ERR, "Domain", "Request host doesn't domain-match finalized domain attribute, discarding cookie")
			return null
		domain_return.host_only_flag = false
		domain_return.domain = domain_attribute
	else:
		domain_return.host_only_flag = true
		domain_return.domain = HTTPUtils.get_url_domain(_current_request_url).to_lower()
	return domain_return


# Gets the finalized path for a storage cookie
func _get_finalized_path(cookie: Dictionary) -> String:
	if (cookie.attributes.has("Path")):
		return cookie.attributes.Path
	else:
		return _get_cookie_default_path(_current_request_url)


# Get the default path for a cookie based off the `requst-uri`
func _get_cookie_default_path(request_uri: String) -> String:
	var uri_path = HTTPUtils.get_url_path(request_uri)
	if (uri_path.is_empty() or uri_path[0] != "/"):
		return "/"
	if (uri_path.count("/") == 1):
		return "/"
	var path_array = uri_path.split("/")
	path_array.remove_at(path_array.size()-1)
	return "/".join(path_array)
