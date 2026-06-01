#ifndef TCP_STREAM_CALLBACK_H
#define TCP_STREAM_CALLBACK_H

#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h>
#include <regex>
#include <string>
#include <iostream>
#include <fstream>
#include <mutex>
#include <curl/curl.h>
#include <algorithm>

#include "./http_state.h"
#include "./db_connect.h"
#include "./network_config.h"
#include "./config.h"

using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

string url_decode(const string &encoded)
{
  auto decode_once = [](const string &input) -> string
  {
    string result;
    result.reserve(input.length());
    for (size_t i = 0; i < input.length(); ++i)
    {
      if (input[i] == '%' && i + 2 < input.length())
      {
        string hex = input.substr(i + 1, 2);
        try
        {
          char c = static_cast<char>(stoi(hex, nullptr, 16));
          result += c;
        }
        catch (const std::exception &e)
        {
          result += "%" + hex;
        }
        i += 2;
      }
      else if (input[i] == '+')
      {
        result += ' ';
      }
      else
      {
        result += input[i];
      }
    }
    return result;
  };

  string result = decode_once(encoded);
  result = decode_once(result);
  return result;
}

string html_entity_decode(const string &data)
{
  string result;
  string temp = data;
  smatch match;

  regex hex_entity(R"(&#[xX]([0-9a-fA-F]+);)");
  while (regex_search(temp, match, hex_entity))
  {
    result += match.prefix().str();
    try {
      int code = stoi(match[1].str(), nullptr, 16);
      result += string(1, static_cast<char>(code));
    } catch (const exception& e) {
      result += match[0].str();
    }
    temp = match.suffix().str();
  }
  result += temp;

  temp = result;
  result = "";
  regex dec_entity(R"(&#([0-9]+);)");
  while (regex_search(temp, match, dec_entity))
  {
    result += match.prefix().str();
    try {
      int code = stoi(match[1].str());
      result += string(1, static_cast<char>(code));
    } catch (const exception& e) {
      result += match[0].str();
    }
    temp = match.suffix().str();
  }
  result += temp;

  result = regex_replace(result, regex("&lt;"), "<");
  result = regex_replace(result, regex("&gt;"), ">");
  result = regex_replace(result, regex("&amp;"), "&");
  result = regex_replace(result, regex("&quot;"), "\"");
  result = regex_replace(result, regex("&apos;"), "'");

  return result;
}

// Forward (client -> server)
void on_client_data(Stream &stream, unordered_map<string, HTTP_State> &httpMap, pqxx::connection &conn, chrono::minutes ips_timeout, AppConfig &app_config)
{
  string client_ip = stream.client_addr_v4().to_string();
  int client_port = stream.client_port();
  string server_ip = stream.server_addr_v4().to_string();
  int server_port = stream.server_port();
  string protocol = "http";

  const Stream::payload_type &payload = stream.client_payload();
  string data(payload.begin(), payload.end());

  string decoded_data = url_decode(data);
  decoded_data = html_entity_decode(decoded_data);
  for (size_t i = 0; i < decoded_data.length(); ++i)
  {
    if (decoded_data[i] == '+') decoded_data[i] = ' ';
  }
  string lower_data = decoded_data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);
  static regex ref_pattern(R"((\r?\n)referer:[^\r\n]*)");
  data = regex_replace(lower_data, ref_pattern, "");

  smatch match;

  // SQL Injection
  bool sql_injection_detected = false;
  static const regex sql_comment_pattern(R"(((?:^|\s)--\s+.*)|(?:^|[\s;])\/\*[\s\S]*?\*\/)"); // Comment
  if (regex_search(lower_data, sql_comment_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Injection Detected (Comment)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Comment Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Comment Injection", "Alert");
    }
  }
  static const regex and_or_pattern(R"((\b(and|or)|\|\||&&)([\s\+]+|\*.*?\*|['"(])+(\w|\s)*([\s\+]|['")])*(?:!=|>=|<=|=|>|<|like)+)"); // AND OR
  if (regex_search(lower_data, and_or_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Injection Detected (AND/OR)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "AND/OR Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "AND/OR Injection", "Alert");
    }
  }
  static const regex order_by_pattern(R"(['")\s\+]*\b(order|ororderder)\b[\s\+]*\bby\b[\s\+]*\d+[\s\+]*\/\*)"); // Order By
  if (regex_search(lower_data, order_by_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Injection Detected (Order By)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Order By Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Order By Injection", "Alert");
    }
  }
  static const regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
  if (regex_search(lower_data, union_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Injection Detected (UNION)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "UNION Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "UNION Injection", "Alert");
    }
  }
  static const regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function
  if (regex_search(lower_data, call_func_pattern) && !sql_injection_detected)
  {
    sql_injection_detected = true;
    cout << "[ALERT] SQL Injection Detected (Function Call)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Function Call Injection", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "SQL Injection", "Function Call Injection", "Alert");
    }
  }

  // Cross Site Scripting (XSS)
  bool xss_detected = false;
  static const regex script_injection_pattern(
      "<\\s*script[^>]*>"              // <script ...>
      "|<\\s*/\\s*script\\s*>"         // </script>
      "|%(3c|3C)\\s*script"            // %3cscript (URL-encoded)
      "|<\\s*\\w+\\s+<\\s*script"      // <tag <script  (split evasion)
      "|<\\s*/\\s*\\w+\\s+<\\s*script" // </tag <script
      "|<\\s*\\w+\\s+</\\s*script"     // <tag </script
  );
  if (regex_search(lower_data, script_injection_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Script Tag)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Script Tag", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Script Tag", "Alert");
    }
  }

  static const regex protocol_injection_pattern(
      "(javascript|vbscript|data)\\s*:"      // javascript: / vbscript: / data:
      "|href\\s*=\\s*[\"']?\\s*java\\s*[:&]" // href="java: หรือ java&colon;
  );
  if (regex_search(lower_data, protocol_injection_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Protocol Handler)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Protocol Handler", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Protocol Handler", "Alert");
    }
  }

  static const regex css_xss_pattern(
      "x?\\s*expression\\s*\\("                          // expression( / xpression(
      "|/\\s*x\\s*pression\\s*\\("                       // /xpression( (split evasion)
      "|style\\s*=.*(font-family|expression)[^;]*['\"(]" // style= ที่มี expression
      "|url\\s*\\(\\s*javascript:"                       // url(javascript:
      "|behavior\\s*:"                                   // behavior: (IE)
      "|moz-binding\\s*:"                                // -moz-binding: (Firefox)
  );
  if (regex_search(lower_data, css_xss_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (CSS)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "CSS", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "CSS", "Alert");
    }
  }

  static const regex event_injection_pattern(
      "\\bon(load|error|click|mouseover|mouseout|focus|blur|submit"
      "|change|input|keydown|keyup|keypress|dblclick|drag|drop|scroll"
      "|touchstart|touchend|animationstart|transitionend)\\s*=" // onXXX=
      "|%(6f|6F)(6e|6E)(4c|6c)(4F|6f)(41|61)(44|64)(%3d|=)"     // %6f%6e%6c%6f%61%64= (onload)
  );
  if (regex_search(lower_data, event_injection_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Event Handler)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Event Handler", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Event Handler", "Alert");
    }
  }

  static const regex js_execution_pattern(
      "\\b(alert|prompt|confirm|eval|setTimeout|setInterval"
      "|Function|document\\.write|innerHTML|outerHTML|execScript)\\s*\\(" // dangerous functions
      "|\\b(document\\.cookie|document\\.domain"
      "|window\\.location|document\\.location|window\\.name)\\b" // DOM access
      "|alert\\s*;\\s*pg\\s*\\("                                 // obfuscated alert;pg(
  );
  if (regex_search(lower_data, js_execution_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (JavaScript Execution)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "JavaScript Execution", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "JavaScript Execution", "Alert");
    }
  }

  static const regex dangerous_tag_pattern(
    "<\\s*(img|iframe|svg|object|embed|video|audio|body|input|marquee"
    "|isindex|form|button|select|textarea|table|div|span|a|font|center"
    "|applet|frameset|frame|layer|style|base|link|meta)"
  );
  if (regex_search(lower_data, dangerous_tag_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Dangerous HTML Tag)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Dangerous HTML Tag", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Dangerous HTML Tag", "Alert");
    }
  }

  static const regex obfuscation_pattern(
      "String\\.fromCharCode"                       // String.fromCharCode(...)
      "|\\\\x[0-9a-fA-F]{2}"                        // \x41
      "|\\\\u[0-9a-fA-F]{4}"                        // \u0041
      "|&#[0-9]+;"                                  // &#65;
      "|&#x[0-9a-fA-F]+;"                           // &#x41;
      "|x-imap4-modified-utf7.*(script|alert|java)" // IMAP4 UTF-7 bypass
  );
  if (regex_search(lower_data, obfuscation_pattern) && !xss_detected)
  {
    xss_detected = true;
    cout << "[ALERT] XSS Detected (Obfuscation)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Obfuscation", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "XSS", "Obfuscation", "Alert");
    }
  }

  // Directory Traversal
  bool access_control_detected = false;
  static const regex path_traversal_pattern(
    R"((?:\.\.?[/\\]|\.\.[/\\])(?:(?:\.\.?[/\\]|\.\.[/\\]))*)"
  );
  if (regex_search(lower_data, path_traversal_pattern) && !access_control_detected && !xss_detected)
  {
    access_control_detected = true;
    cout << "[ALERT] Directory Traversal Detected" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Directory Traversal", "Path Traversal", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Directory Traversal", "Path Traversal", "Alert");
    }
  }

  static const regex lfi_pattern(
    R"((etc\/(passwd|shadow|hosts|group|issue|htgroup)|[c-z]:\\|boot\.ini|win\.ini|\.htaccess|cmd\.exe|global\.asa|desktop\.ini|bin\/(cat|id|ls|sh|bash)|winnt|system32))"
  );
  if (regex_search(lower_data, lfi_pattern) && !access_control_detected && !xss_detected)
  {
    access_control_detected = true;
    cout << "[ALERT] Local File Inclusion Detected (LFI)" << endl;
    if (app_config.mode)
    {
      block_ip(client_ip, ips_timeout);
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Directory Traversal", "Local File Inclusion (LFI)", "Block");
    }
    else
    {
      log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Directory Traversal", "Local File Inclusion (LFI)", "Alert");
    }
  }

  // Brute Force
  static regex http_start_pattern(R"(^(get|post|put|delete|head|options|patch)[\s\+]+([^?\s]+))");
  smatch url_match;

  if (regex_search(lower_data, url_match, http_start_pattern))
  {
    string url_path = url_match[0].str();
    string client_ip = stream.client_addr_v4().to_string();

    if (httpMap.find(client_ip) == httpMap.end())
    {
      // Create HTTP State
      HTTP_State newState;
      newState.ip = client_ip;
      newState.first_seen = chrono::system_clock::now();
      httpMap[client_ip] = newState;
    }

    // Update HTTP State
    HTTP_State &http = httpMap[client_ip];
    http.last_seen = chrono::system_clock::now();
    http.pending_path = url_path;
    if (http.apiMap.find(url_path) == http.apiMap.end())
    {
      static const size_t MAX_TRACKED_PATHS = 256;
      if (http.apiMap.size() >= MAX_TRACKED_PATHS)
      {
        http.apiMap.erase(http.apiMap.begin());
      }
      http.apiMap[url_path] = vector<int>();
    }
  }
}

// Backward (server -> client)
void on_server_data(Stream &stream, unordered_map<string, HTTP_State> &httpMap, pqxx::connection &conn, chrono::minutes ips_timeout, AppConfig &app_config)
{
  string client_ip = stream.client_addr_v4().to_string();
  int client_port = stream.client_port();
  string server_ip = stream.server_addr_v4().to_string();
  int server_port = stream.server_port();
  string protocol = "http";

  auto it_http = httpMap.find(client_ip);
  if (it_http == httpMap.end())
    return;

  HTTP_State &http = it_http->second;
  const Stream::payload_type &payload = stream.server_payload();
  if (payload.empty())
    return;
  string pending_path = http.pending_path;
  http.apiMap[pending_path].push_back(payload.size());
  if (http.apiMap[pending_path].size() > 10)
    http.apiMap[pending_path].erase(http.apiMap[pending_path].begin());

  if (http.apiMap[pending_path].size() == 10)
  {
    vector<int> &lengths = http.apiMap[pending_path];
    auto result = minmax_element(lengths.begin(), lengths.end());
    int min_val = *result.first;
    int max_val = *result.second;

    int range = max_val - min_val;
    if (range >= 0 && range <= app_config.http_byte_len_limit)
    {
      if (http.http_brute_force == false)
      {
        cout << "[ALERT] Web Brute Force Detected" << endl;
        if (app_config.mode && http.http_brute_force == false)
        {
          block_ip(client_ip, ips_timeout);
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "Web Brute Force", "Block");
          http.http_brute_force = true;
        }
        else
        {
          log_attack_to_db(conn, client_ip, client_port, server_ip, server_port, protocol, "Brute Force", "Web Brute Force", "Alert");
          http.http_brute_force = true;
        }
      }
    }
  }
}

#endif