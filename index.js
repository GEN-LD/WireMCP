// index.js - WireMCP Server
const axios = require('axios');
// 【安全修复】将 exec 替换为 execFile，避免用户输入通过系统 shell 执行，从根本上消除命令注入风险
// exec 会将命令字符串传给 /bin/sh 执行，攻击者可通过 shell 元字符（;、&&、| 等）注入任意命令
// execFile 直接调用目标程序，参数以数组形式传递，不经过 shell 解析，彻底阻断注入路径
const { execFile } = require('child_process');
const { promisify } = require('util');
const which = require('which');
const fs = require('fs').promises;
const crypto = require('crypto');
const path = require('path');
const os = require('os');
// 【安全修复】将 promisify 的底层从 exec 改为 execFile，保证所有调用点使用安全的参数传递方式
const execFileAsync = promisify(execFile);
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const express = require('express');

// Redirect console.log to stderr
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);

// 【安全修复】输入白名单校验函数，防止攻击者通过恶意输入构造 shell 注入载荷
// 在所有使用用户输入调用系统命令之前，必须先经过这些校验函数

/**
 * 校验网络接口名称
 * 仅允许字母、数字、下划线、连字符、点号，长度不超过 64 字符
 * 阻止如 "eth0; whoami" 这类包含 shell 元字符的注入尝试
 */
function validateInterface(name) {
  if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) {
    throw new Error(`非法的网络接口名称: "${name}"。仅允许字母、数字、下划线、连字符和点号。`);
  }
  return name;
}

/**
 * 校验捕获时长
 * 仅允许 1~60 之间的整数，防止注入如 "5; cat /etc/passwd" 的非数字字符串
 */
function validateDuration(d) {
  if (!Number.isInteger(d) || d < 1 || d > 60) {
    throw new Error(`捕获时长必须是 1~60 之间的整数，当前值: ${d}`);
  }
  return d;
}

/**
 * 校验 pcap 文件路径
 * 规范化为绝对路径，禁止路径穿越（包含 ".."），并检查文件是否存在
 */
async function validatePcapPath(p) {
  const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

  if (typeof p !== 'string' || p.includes('..') || p.includes('\0')) {
    throw new Error(`非法的文件路径: "${p}"。路径中不允许包含 ".." 或空字符。`);
  }
  const resolved = path.resolve(p);
  const ext = path.extname(resolved).toLowerCase();

  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    throw new Error(
      `不支持的文件扩展名: "${ext}"。仅允许以下扩展名: ${ALLOWED_EXTENSIONS.join(', ')}\n` +
      `请确保文件为标准的 PCAP 格式。`
    );
  }

  await fs.access(resolved);
  return resolved;
}

/**
 * 解码 tshark 输出中的十六进制字段
 * tshark -T fields 模式下，二进制类型字段（如 http.file_data、tcp.payload）输出为十六进制字符串
 * 大模型无法直接理解长 hex 串，需要自动解码为可读文本
 *
 * 判断逻辑：
 * 1. 长度 >= 8 且为偶数（每2个hex字符=1字节）
 * 2. 只包含 0-9a-f 字符
 * 3. 解码后可打印字符占比 > 80%，视为文本内容，输出解码结果
 * 4. 否则视为二进制数据，保留原始 hex 并标注 [binary data]
 *
 * @param {string} output - tshark 原始输出
 * @returns {string} 解码后的输出
 */
function decodeHexFields(output) {
  const HEX_MIN_LENGTH = 8;
  const PRINTABLE_RATIO_THRESHOLD = 0.8;

  return output.split('\n').map(line => {
    return line.split('\t').map(field => {
      // 快速排除：长度不足或非偶数
      if (field.length < HEX_MIN_LENGTH || field.length % 2 !== 0) return field;
      // 快速排除：包含非hex字符
      if (!/^[0-9a-f]+$/i.test(field)) return field;

      // 尝试 hex 解码
      try {
        const decoded = Buffer.from(field, 'hex').toString('utf-8');
        // 计算可打印字符占比
        let printable = 0;
        for (let i = 0; i < decoded.length; i++) {
          const code = decoded.charCodeAt(i);
          // 可打印范围：空格(0x20)~波浪号(0x7E)，加上 \r \n \t
          if ((code >= 0x20 && code <= 0x7E) || code === 0x0D || code === 0x0A || code === 0x09) {
            printable++;
          }
        }
        const ratio = printable / decoded.length;
        if (ratio >= PRINTABLE_RATIO_THRESHOLD) {
          return decoded;
        } else {
          return field + ' [binary data]';
        }
      } catch {
        return field;
      }
    }).join('\t');
  }).join('\n');
}

/**
 * 解析 tshark 参数为数组
 * @param {string} args - 用户输入的参数字符串
 * @returns {string[]}
 */
function parseTsharkArgs(args) {
  const argArray = [];
  const regex = /[^\s"']+|"([^"]*)"|'([^']*)'/g;
  let match;
  while ((match = regex.exec(args)) !== null) {
    const value = match[1] || match[2] || match[0];
    if (value) argArray.push(value);
  }
  return argArray;
}

/**
 * 校验 tshark 参数数组，阻止危险参数注入
 * 当检测到命令注入等不当使用行为时，抛错并给出合法替代方案建议
 * @param {string[]} args - 解析后的参数数组
 * @throws {Error} 当包含危险参数时抛出详细错误
 */
function validateTsharkArgs(args) {
  const dangerousParams = {
    '-X': {
      patterns: ['-X', '--lua-script', '--export-objects'],
      reason: '可能执行任意 Lua 脚本或导出文件到任意目录，存在代码执行和文件系统风险',
      alternatives: [
        '使用 -T fields -e <field> 提取特定协议字段数据（如 -T fields -e http.request.uri）',
        '使用 -Y "<filter>" 进行显示过滤分析（如 -Y "http.request.method == GET"）',
        '使用 -V 查看完整协议解码详情',
        '使用 -z io,phs 生成协议层级统计报告',
        '使用 -z follow,tcp,ascii,0 追踪 TCP 流内容'
      ]
    },
    '-o': {
      patterns: ['-o', '--override-prefs'],
      reason: '可能覆盖关键偏好设置导致非预期行为或安全策略绕过',
      alternatives: [
        '使用 -Y "<filter>" 精确控制显示内容范围',
        '使用 -O <protocol> 仅详细显示指定协议（如 -O http）',
        '使用 -T fields -e <field> 精确提取所需字段，避免多余输出'
      ]
    },
    '-C': {
      patterns: ['-C', '--configuration-profile'],
      reason: '可能加载包含恶意配置的配置文件，导致非预期行为',
      alternatives: [
        '使用标准过滤器和字段提取参数替代自定义配置',
        '使用 -Y "<filter>" 和 -e <field> 组合实现分析目标',
        '使用 -T json 输出结构化数据便于分析'
      ]
    },
    '-r': {
      patterns: ['-r', '--read-file'],
      reason: '可能覆盖 PCAP 文件路径，读取非授权或恶意构造的文件',
      alternatives: [
        'PCAP 文件路径已通过 pcapPath 参数指定，无需在 tsharkArgs 中重复设置 -r',
        '如需分析多个文件，请多次调用 exec_tshark 工具，每次指定不同 pcapPath',
        '如需合并分析，请使用其他工具在调用前合并 PCAP 文件'
      ]
    },
    '-w': {
      patterns: ['-w', '--write-file'],
      reason: '可能在系统任意位置写入文件，覆盖关键系统文件或造成磁盘耗尽',
      alternatives: [
        '使用 -T fields -e <field> 提取数据到标准输出，结果已在返回的文本中',
        '使用 -T json 输出结构化 JSON 数据，便于客户端解析和保存',
        '使用 -T pdml 输出 Packet Details Markup Language 格式',
        '如需保存结果，请在客户端保存工具返回的文本内容'
      ]
    },
    '-F': {
      patterns: ['-F'],
      reason: '可能生成非预期的输出格式文件，通常配合 -w 使用造成文件操作风险',
      alternatives: [
        '使用 -T <format> 控制文本输出格式（支持 fields, json, pdml, text, ps, psml）',
        '输出内容已包含在工具返回结果中，无需额外写入文件'
      ]
    },
    '-b': {
      patterns: ['-b', '--ring-buffer'],
      reason: '可能在磁盘上创建多个捕获文件，造成磁盘空间耗尽或服务拒绝',
      alternatives: [
        '使用 -c <count> 限制读取的数据包数量（如 -c 1000）',
        '使用 -Y "<filter>" 过滤后再分析，减少处理的数据量',
        '通过返回结果在内存中分析数据，无需本地存储中间文件'
      ]
    },
    '-U': {
      patterns: ['-U', '--update-interval'],
      reason: '通常配合文件写入使用（如 -w），可能导致持续性的文件操作风险',
      alternatives: [
        '直接读取已存在的完整 pcap 文件，无需实时更新',
        '如需持续监控，请使用 capture_packets 工具进行实时捕获'
      ]
    }
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    let violationKey = null;
    let matchedPattern = null;

    if (typeof arg !== 'string') continue;

    if (arg.length >= 2 && arg[0] === '-' && arg[1] !== '-') {
      const shortFlags = Object.keys(dangerousParams);
      for (const flag of shortFlags) {
        if (arg === flag) {
          violationKey = flag;
          matchedPattern = arg;
          break;
        }
        if (arg.startsWith(flag) && arg.length > flag.length) {
          const nextChar = arg[flag.length];
          if (nextChar !== undefined && nextChar !== ' ') {
            violationKey = flag;
            matchedPattern = arg;
            break;
          }
        }
      }
    }

    if (!violationKey) {
      for (const [key, info] of Object.entries(dangerousParams)) {
        for (const pattern of info.patterns) {
          if (pattern.startsWith('--')) {
            if (arg === pattern || arg.startsWith(`${pattern}=`) || arg.startsWith(`${pattern}:`)) {
              violationKey = key;
              matchedPattern = arg;
              break;
            }
          }
        }
        if (violationKey) break;
      }
    }

    if (!violationKey && (arg.startsWith('-X:') || arg.startsWith('-X='))) {
      violationKey = '-X';
      matchedPattern = arg;
    }

    if (violationKey) {
      const info = dangerousParams[violationKey];
      const alternatives = info.alternatives.map(a => `  • ${a}`).join('\n');
      throw new Error(
        `【安全拦截】检测到危险参数 "${matchedPattern}"。\n` +
        `风险说明：${info.reason}\n` +
        `为了保障系统安全，已禁止在自定义 tshark 参数中使用此选项。\n\n` +
        `您可以尝试以下合法替代方案来达到相同的分析效果：\n${alternatives}\n\n` +
        `如需了解完整的 tshark 参数用法，请参考工具描述中的参数示例。`
      );
    }
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-Y' || args[i] === '--display-filter') {
      if (i + 1 < args.length) {
        const filterValue = args[i + 1];
        if (typeof filterValue === 'string' && (filterValue.includes('\0') || filterValue.includes('\n'))) {
          throw new Error(
            `【安全拦截】检测到过滤表达式包含非法字符（空字符或换行符）。\n` +
            `请使用标准的 Wireshark 显示过滤器语法，例如：\n` +
            `  • ip.addr == 192.168.1.1\n` +
            `  • http.request.method == "GET"\n` +
            `  • tcp.port == 80 && http.host contains "example"\n` +
            `  • dns.qry.name matches ".*\\.example\\.com"\n` +
            `  • frame.len > 1000`
          );
        }
      }
    }
  }
}

/** * 生成安全的临时文件路径
 * 使用 os.tmpdir() + 唯一文件名，避免硬编码文件名被猜到或产生冲突
 */
function createTempPcapPath() {
  return path.join(os.tmpdir(), `wiremcp_${crypto.randomUUID()}.pcap`);
}

// Dynamically locate tshark
async function findTshark() {
  try {
    const tsharkPath = await which('tshark');
    console.error(`Found tshark at: ${tsharkPath}`);
    return tsharkPath;
  } catch (err) {
    console.error('which failed to find tshark:', err.message);
    const fallbacks = process.platform === 'win32'
      ? ['C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe']
      : ['/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark', '/Applications/Wireshark.app/Contents/MacOS/tshark'];
    
    for (const candidate of fallbacks) {
      try {
        // 【安全修复】使用 execFileAsync 替代 execAsync，避免 tshark 路径拼接字符串经过 shell 解析
        await execFileAsync(candidate, ['-v']);
        console.error(`Found tshark at fallback: ${candidate}`);
        return candidate;
      } catch (e) {
        console.error(`Fallback ${path} failed: ${e.message}`);
      }
    }
    throw new Error('tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH.');
  }
}

// Register tools with the given server instance
function registerTools(server) {
  // Tool 1: Capture live packet data
  server.tool(
  'capture_packets',
  'Capture live traffic and provide raw packet data as JSON for LLM analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      // 【安全修复】对用户输入的 interface 和 duration 进行白名单校验，阻止 shell 注入
      validateInterface(interface);
      validateDuration(duration);
      // 【安全修复】使用安全的临时文件路径，避免硬编码文件名被利用
      const tempPcap = createTempPcapPath();
      console.error(`Capturing packets on ${interface} for ${duration}s`);

      // 【安全修复】使用 execFileAsync + 参数数组替代 execAsync + 字符串拼接
      // execFile 不经过系统 shell，参数直接传递给 tshark 进程，阻断注入路径
      await execFileAsync(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', tempPcap, '-T', 'json', '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'tcp.flags', '-e', 'frame.time', '-e', 'http.request.method', '-e', 'http.response.code'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);
      let packets = JSON.parse(stdout);

      const maxChars = 720000;
      let jsonString = JSON.stringify(packets);
      if (jsonString.length > maxChars) {
        const trimFactor = maxChars / jsonString.length;
        const trimCount = Math.floor(packets.length * trimFactor);
        packets = packets.slice(0, trimCount);
        jsonString = JSON.stringify(packets);
        console.error(`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`);
      }

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `Captured packet data (JSON for LLM analysis):\n${jsonString}`,
        }],
      };
    } catch (error) {
      console.error(`Error in capture_packets: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 2: Analyze a PCAP file and provide protocol hierarchy statistics
server.tool(
  'get_summary_stats',
  'Analyze a PCAP file and provide protocol hierarchy statistics for LLM analysis',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath } = args;
      console.error(`Analyzing summary stats for PCAP: ${pcapPath}`);

      // 【安全修复】使用 validatePcapPath 替代 fs.access，一并完成路径规范化、安全检查和存在性验证
      const safePcapPath = await validatePcapPath(pcapPath);

      // 【安全修复】使用 execFileAsync + 参数数组，pcapPath 作为独立参数传入，不经过 shell
      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', safePcapPath, '-qz', 'io,phs'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      return {
        content: [{
          type: 'text',
          text: `Analyzed PCAP: ${pcapPath}\n\nProtocol hierarchy statistics:\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_summary_stats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 3: Capture and provide conversation stats
server.tool(
  'get_conversations',
  'Analyze a PCAP file and provide TCP conversation statistics for LLM analysis',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath } = args;
      console.error(`Analyzing conversations in PCAP: ${pcapPath}`);

      // 【路径安全处理】规范化路径并校验扩展名，防止路径穿越和文件类型混淆攻击
      const safePcapPath = await validatePcapPath(pcapPath);

      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', safePcapPath, '-qz', 'conv,tcp'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      // 【输出大小限制】防止超大数据量导致LLM上下文溢出，超过100K字符时自动截断
      const maxChars = 100000;
      let output = stdout;
      if (output.length > maxChars) {
        const originalLength = output.length;
        output = output.slice(0, maxChars) +
          `\n\n[数据已截断] 原始大小: ${originalLength} 字符, 截断后大小: ${maxChars} 字符, 截断方式: 保留前 ${maxChars} 字符`;
        console.error(`输出已从 ${originalLength} 字符截断到 ${maxChars} 字符`);
      }

      return {
        content: [{
          type: 'text',
          text: `TCP conversation statistics for LLM analysis:\n${output}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_conversations: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 4: Capture traffic and check threats against URLhaus
server.tool(
  'check_threats',
  'Capture live traffic and check IPs against URLhaus blacklist',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      // 【安全修复】白名单校验用户输入，防止命令注入
      validateInterface(interface);
      validateDuration(duration);
      const tempPcap = createTempPcapPath();
      console.error(`Capturing traffic on ${interface} for ${duration}s to check threats`);

      // 【安全修复】使用 execFileAsync 参数数组方式调用，绕过 shell 解析
      await execFileAsync(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout } = await execFileAsync(
        tsharkPath,
        ['-r', tempPcap, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const ips = [...new Set(stdout.split('\n').flatMap(line => line.split('\t')).filter(ip => ip && ip !== 'unknown'))];
      console.error(`Captured ${ips.length} unique IPs: ${ips.join(', ')}`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let urlhausThreats = [];
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        urlhausThreats = ips.filter(ip => urlhausData.includes(ip));
        console.error(`Checked IPs against URLhaus: ${urlhausThreats.length} threats found - ${urlhausThreats.join(', ') || 'None'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `Captured IPs:\n${ips.join('\n')}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          urlhausThreats.length > 0 ? `Potential threats: ${urlhausThreats.join(', ')}` : 'No threats detected in URLhaus blacklist.'
        }`;

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 5: Check a specific IP against URLhaus IOCs
server.tool(
  'check_ip_threats',
  'Check a given IP address against URLhaus blacklist for IOCs',
  {
    ip: z.string().regex(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/).describe('IP address to check (e.g., 192.168.1.1)'),
  },
  async (args) => {
    try {
      const { ip } = args;
      console.error(`Checking IP ${ip} against URLhaus blacklist`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let isThreat = false;
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        isThreat = urlhausData.includes(ip);
        console.error(`IP ${ip} checked against URLhaus: ${isThreat ? 'Threat found' : 'No threat found'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `IP checked: ${ip}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          isThreat ? 'Potential threat detected in URLhaus blacklist.' : 'No threat detected in URLhaus blacklist.'
        }`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_ip_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// 工具6: 在PCAP文件上执行自定义tshark命令
// 【功能说明】当WireMCP其他内置工具无法满足特定分析需求时，提供高级自定义分析能力
// 【适用场景】复杂过滤、特定字段提取、自定义统计分析等特殊分析需求
// 【注意事项】优先使用内置工具（如analyze_pcap、extract_credentials等），内置工具无法满足时再使用本工具
server.tool(
  'exec_tshark',
  'Execute a custom tshark command on a PCAP file for advanced network analysis when other tools are insufficient. NOTE: For HTTP content extraction, use "http.file_data" instead of "data-text-lines" (which only returns summaries). IMPORTANT: Filter values containing spaces or logical operators (&&, ||, !) MUST be wrapped in quotes, e.g., -Y "tcp.port == 80 && http.host contains \\"example\\""',
  {
    pcapPath: z.string().describe('待分析的PCAP文件路径，例如：./demo.pcap'),
    tsharkArgs: z.string().describe('tshark命令参数字符串，必须用引号包裹。如果参数内部也包含引号，需要转义。示例："-T fields -e http.host -Y \\"http.request.uri contains \\\\\\"flag\\\\\\"\\""。注意：所有包含空格或逻辑运算符（&&、||、!）的 -Y 过滤值都必须用引号包裹，例如：-Y \\"tcp.port == 80 && http.request.method == GET\\"'),
  },
  async (args) => {
    try {
      // 查找tshark可执行文件路径
      const tsharkPath = await findTshark();
      const { pcapPath, tsharkArgs } = args;
      console.error(`执行自定义tshark命令: ${tsharkArgs}`);
      console.error(`分析PCAP文件: ${pcapPath}`);

      // 【路径安全处理】规范化路径并校验扩展名，防止路径穿越和文件类型混淆攻击
      const safePcapPath = await validatePcapPath(pcapPath);

      // 【参数解析】将用户输入的参数字符串解析为安全的参数数组
      // 支持带引号的参数，例如：-Y "http.request.method == GET"
      const argsArray = parseTsharkArgs(tsharkArgs);

      // 【参数安全校验】检测并阻止危险参数注入，发现不当使用时给出合法替代方案
      validateTsharkArgs(argsArray);

      // 【构建完整命令参数】自动添加-r参数读取指定pcap文件，再拼接用户自定义参数
      // 由于已校验 argsArray 不含 -r/--read-file，不会覆盖安全路径
      const fullArgs = ['-r', safePcapPath, ...argsArray];

      // 【安全执行】使用execFileAsync执行命令，不经过shell解析，从根本上避免命令注入风险
      // 设置10MB缓冲区，支持较大的分析结果输出
      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        fullArgs,
        {
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
        }
      );
      if (stderr) console.error(`tshark标准错误输出: ${stderr}`);

      // 【十六进制解码】tshark -T fields 模式下二进制字段输出为hex，大模型无法直接理解
      // 自动检测hex字段并解码为可读文本，二进制数据保留原始hex并标注[binary data]
      let output = decodeHexFields(stdout);

      // 【输出大小限制】防止超大数据量导致LLM上下文溢出，超过720K字符时自动截断
      const maxChars = 720000;
      if (output.length > maxChars) {
        const originalLength = output.length;
        output = output.slice(0, maxChars) + '\n... [输出已截断，数据量超过上下文限制]';
        console.error(`输出已从 ${originalLength} 字符截断到 ${maxChars} 字符`);
      }

      // 【结果格式化】整理输出信息，方便LLM分析使用
      const outputText = `执行的tshark命令: tshark -r ${pcapPath} ${tsharkArgs}\n\n` +
        `分析结果:\n${output}\n\n` +
        `【分析提示】请根据上述输出数据进行网络流量分析，识别异常通信模式、协议特征、敏感信息泄露或安全攻击行为。`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`exec_tshark执行错误: ${error.message}`);
      return { content: [{ type: 'text', text: `执行错误: ${error.message}` }], isError: true };
    }
  }
);

// Tool 7: Analyze an existing PCAP file for general context
server.tool(
  'analyze_pcap',
  'Analyze a PCAP file and provide general packet data as JSON for LLM analysis',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath } = args;
      console.error(`Analyzing PCAP file: ${pcapPath}`);

      // 【安全修复】使用 validatePcapPath 替代 fs.access，一并完成路径规范化、安全检查和存在性验证
      const safePcapPath = await validatePcapPath(pcapPath);

      // 【安全修复】使用 execFileAsync + 参数数组，pcapPath 作为独立参数传入，不经过 shell
      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', safePcapPath, '-T', 'json', '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'udp.srcport', '-e', 'udp.dstport', '-e', 'http.host', '-e', 'http.request.uri', '-e', 'frame.protocols'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);
      const packets = JSON.parse(stdout);

      const ips = [...new Set(packets.flatMap(p => [
        p._source?.layers['ip.src']?.[0],
        p._source?.layers['ip.dst']?.[0]
      ]).filter(ip => ip))];
      console.error(`Found ${ips.length} unique IPs: ${ips.join(', ')}`);

      const urls = packets
        .filter(p => p._source?.layers['http.host'] && p._source?.layers['http.request.uri'])
        .map(p => `http://${p._source.layers['http.host'][0]}${p._source.layers['http.request.uri'][0]}`);
      console.error(`Found ${urls.length} URLs: ${urls.join(', ') || 'None'}`);

      const protocols = [...new Set(packets.map(p => p._source?.layers['frame.protocols']?.[0]))].filter(p => p);
      console.error(`Found protocols: ${protocols.join(', ') || 'None'}`);

      const maxChars = 200000;
      const totalPackets = packets.length;
      let jsonString = JSON.stringify(packets);
      const originalSize = jsonString.length;
      let trimmed = false;
      let trimCount = totalPackets;
      if (jsonString.length > maxChars) {
        const trimFactor = maxChars / jsonString.length;
        trimCount = Math.floor(packets.length * trimFactor);
        packets.splice(trimCount);
        jsonString = JSON.stringify(packets);
        trimmed = true;
        console.error(`Trimmed packets from ${totalPackets} to ${trimCount} to fit ${maxChars} chars`);
      }

      const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
        `Unique IPs:\n${ips.join('\n')}\n\n` +
        `URLs:\n${urls.length > 0 ? urls.join('\n') : 'None'}\n\n` +
        `Protocols:\n${protocols.join('\n') || 'None'}\n\n` +
        `Data Truncation Info:\n` +
        `  - Original JSON size: ${(originalSize / 1024).toFixed(1)} KB (${originalSize} chars)\n` +
        `  - Truncated: ${trimmed ? 'Yes' : 'No'}\n` +
        (trimmed ? `  - Truncated size: ${(jsonString.length / 1024).toFixed(1)} KB (${jsonString.length} chars)\n` +
        `  - Retained: First ${trimCount} of ${totalPackets} packets (from the beginning of the capture)\n` : '') +
        `\nPacket Data (JSON for LLM):\n${jsonString}`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in analyze_pcap: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 8: Extract credentials from a PCAP file
server.tool(
    'extract_credentials',
    'Extract potential credentials (HTTP Basic Auth, FTP, Telnet) from a PCAP file for LLM analysis',
    {
      pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapPath } = args;
        console.error(`Extracting credentials from PCAP file: ${pcapPath}`);
  
        // 【安全修复】使用 validatePcapPath 替代 fs.access，一并完成路径规范化、安全检查和存在性验证
        const safePcapPath = await validatePcapPath(pcapPath);
  
        // 【安全修复】使用 execFileAsync + 参数数组，pcapPath 作为独立参数传入，不经过 shell
        const { stdout: plaintextOut } = await execFileAsync(
          tsharkPath,
          ['-r', safePcapPath, '-T', 'fields', '-e', 'http.authbasic', '-e', 'ftp.request.command', '-e', 'ftp.request.arg', '-e', 'telnet.data', '-e', 'frame.number'],
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        // 【安全修复】同上，使用 execFileAsync 参数数组方式提取 Kerberos 凭据
        const { stdout: kerberosOut } = await execFileAsync(
          tsharkPath,
          ['-r', safePcapPath, '-T', 'fields', '-e', 'kerberos.CNameString', '-e', 'kerberos.realm', '-e', 'kerberos.cipher', '-e', 'kerberos.type', '-e', 'kerberos.msg_type', '-e', 'frame.number'],
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        const lines = plaintextOut.split('\n').filter(line => line.trim());
        const packets = lines.map(line => {
          const [authBasic, ftpCmd, ftpArg, telnetData, frameNumber] = line.split('\t');
          return {
            authBasic: authBasic || '',
            ftpCmd: ftpCmd || '',
            ftpArg: ftpArg || '',
            telnetData: telnetData || '',
            frameNumber: frameNumber || ''
          };
        });
  
        const credentials = {
          plaintext: [],
          encrypted: []
        };
  
        // Process HTTP Basic Auth
        packets.forEach(p => {
          if (p.authBasic) {
            const [username, password] = Buffer.from(p.authBasic, 'base64').toString().split(':');
            credentials.plaintext.push({ type: 'HTTP Basic Auth', username, password, frame: p.frameNumber });
          }
        });
  
        // Process FTP
        packets.forEach(p => {
          if (p.ftpCmd === 'USER') {
            credentials.plaintext.push({ type: 'FTP', username: p.ftpArg, password: '', frame: p.frameNumber });
          }
          if (p.ftpCmd === 'PASS') {
            const lastUser = credentials.plaintext.findLast(c => c.type === 'FTP' && !c.password);
            if (lastUser) lastUser.password = p.ftpArg;
          }
        });
  
        // Process Telnet
        packets.forEach(p => {
          if (p.telnetData) {
            const telnetStr = p.telnetData.trim();
            if (telnetStr.toLowerCase().includes('login:') || telnetStr.toLowerCase().includes('password:')) {
              credentials.plaintext.push({ type: 'Telnet Prompt', data: telnetStr, frame: p.frameNumber });
            } else if (telnetStr && !telnetStr.match(/[A-Z][a-z]+:/) && !telnetStr.includes(' ')) {
              const lastPrompt = credentials.plaintext.findLast(c => c.type === 'Telnet Prompt');
              if (lastPrompt && lastPrompt.data.toLowerCase().includes('login:')) {
                credentials.plaintext.push({ type: 'Telnet', username: telnetStr, password: '', frame: p.frameNumber });
              } else if (lastPrompt && lastPrompt.data.toLowerCase().includes('password:')) {
                const lastUser = credentials.plaintext.findLast(c => c.type === 'Telnet' && !c.password);
                if (lastUser) lastUser.password = telnetStr;
                else credentials.plaintext.push({ type: 'Telnet', username: '', password: telnetStr, frame: p.frameNumber });
              }
            }
          }
        });

        // Process Kerberos credentials
        const kerberosLines = kerberosOut.split('\n').filter(line => line.trim());
        kerberosLines.forEach(line => {
          const [cname, realm, cipher, type, msgType, frameNumber] = line.split('\t');
          
          if (cipher && type) {
            let hashFormat = '';
            // Format hash based on message type
            if (msgType === '10' || msgType === '30') { // AS-REQ or TGS-REQ
              hashFormat = '$krb5pa$23$';
              if (cname) hashFormat += `${cname}$`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            } else if (msgType === '11') { // AS-REP
              hashFormat = '$krb5asrep$23$';
              if (cname) hashFormat += `${cname}@`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            }

            if (hashFormat) {
              credentials.encrypted.push({
                type: 'Kerberos',
                hash: hashFormat,
                username: cname || 'unknown',
                realm: realm || 'unknown',
                frame: frameNumber,
                crackingMode: msgType === '11' ? 'hashcat -m 18200' : 'hashcat -m 7500'
              });
            }
          }
        });

        console.error(`Found ${credentials.plaintext.length} plaintext and ${credentials.encrypted.length} encrypted credentials`);

        const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
          `Plaintext Credentials:\n${credentials.plaintext.length > 0 ?
            credentials.plaintext.map(c =>
              c.type === 'Telnet Prompt' ?
                `${c.type}: ${c.data} (Frame ${c.frame})` :
                `${c.type}: ${c.username}:${c.password} (Frame ${c.frame})`
            ).join('\n') :
            'None'}\n\n` +
          `Encrypted/Hashed Credentials:\n${credentials.encrypted.length > 0 ?
            credentials.encrypted.map(c =>
              `${c.type}: User=${c.username} Realm=${c.realm} (Frame ${c.frame})\n` +
              `Hash=${c.hash}\n` +
              `Cracking Command: ${c.crackingMode}\n`
            ).join('\n') :
            'None'}\n\n` +
          `Note: Encrypted credentials can be cracked using tools like John the Ripper or hashcat.\n` +
          `For Kerberos hashes:\n` +
          `- AS-REQ/TGS-REQ: hashcat -m 7500 or john --format=krb5pa-md5\n` +
          `- AS-REP: hashcat -m 18200 or john --format=krb5asrep`;

        return {
          content: [{ type: 'text', text: outputText }],
        };
      } catch (error) {
        console.error(`Error in extract_credentials: ${error.message}`);
        return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
      }
    }
  );

  // Tool 9: 分析四层网络问题
  server.tool(
    'analyze_l4_network',
    '分析PCAP文件中传输层网络问题。先用tshark过滤命中的数据包，找到关联的TCP流，再逐流分析是否存在SYN无响应、RST拒绝、SYN重传、SYN Flood、超时重传、零窗口、异常RST、挥手不完整等问题。返回JSON格式报告。',
    {
      pcapPath: z.string().describe('待分析的PCAP文件路径，例如：./demo.pcap'),
      tsharkArgs: z.string().describe('tshark命令参数字符串，用于过滤目标数据包。支持 -Y 过滤表达式，例如：-Y "http" 或 -Y "ip.addr == 10.0.0.1"'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapPath, tsharkArgs } = args;
        console.error(`[analyze_l4_network] 开始分析: pcapPath=${pcapPath}, tsharkArgs=${tsharkArgs}`);

        const safePcapPath = await validatePcapPath(pcapPath);
        const parsedArgs = parseTsharkArgs(tsharkArgs);

        // 从用户参数中提取 -Y 过滤器（保留，用于后续分析命令）
        let userFilter = null;
        const cleanArgs = [];
        for (let i = 0; i < parsedArgs.length; i++) {
          if (parsedArgs[i] === '-Y' || parsedArgs[i] === '--display-filter') {
            userFilter = parsedArgs[i + 1] || null;
            i++; // 跳过过滤器值
            continue;
          }
          // 跳过用户传入的 -T / -e / -r 参数（输出格式由本工具控制）
          if (parsedArgs[i] === '-T' || parsedArgs[i] === '-e' || parsedArgs[i] === '-r') {
            i++; // 跳过对应的值
            continue;
          }
          if (parsedArgs[i].startsWith('-T') || parsedArgs[i].startsWith('-e') || parsedArgs[i].startsWith('-r')) continue;
          cleanArgs.push(parsedArgs[i]);
        }

        // ── Step 1: 用用户过滤条件提取命中的 TCP 流编号 ──
        const getStreamsArgs = ['-r', safePcapPath, '-T', 'fields', '-e', 'tcp.stream'];
        if (userFilter) getStreamsArgs.push('-Y', userFilter);

        console.error(`[analyze_l4_network] Step1 提取流编号: ${getStreamsArgs.join(' ')}`);
        const { stdout: streamsOut } = await execFileAsync(tsharkPath, getStreamsArgs, {
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
        });

        const streamIndices = [...new Set(
          streamsOut.split('\n')
            .map(l => l.trim())
            .filter(l => l !== '' && l !== '_')
            .map(Number)
            .filter(n => !isNaN(n))
        )].sort((a, b) => a - b);

        if (streamIndices.length === 0) {
          const result = {
            pcapPath,
            filter: userFilter || null,
            totalStreams: 0,
            issues: [],
            summary: '未找到匹配的TCP流，无法进行四层分析。请检查过滤条件或PCAP文件内容。'
          };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        console.error(`[analyze_l4_network] 发现 ${streamIndices.length} 个TCP流: [${streamIndices.join(', ')}]`);

        // ── Step 2: 逐流批量查询（使用 tshark -z 支持多流统计，减少调用次数）──
        const streamFilter = streamIndices.map(n => `tcp.stream eq ${n}`).join(' || ');
        const combinedFilter = userFilter ? `(${userFilter}) && (${streamFilter})` : streamFilter;

        // 查询 A: 每个流的 TCP flags 汇总
        const { stdout: flagsOut } = await execFileAsync(tsharkPath, [
          '-r', safePcapPath, '-T', 'fields',
          '-e', 'tcp.stream', '-e', 'tcp.flags', '-e', 'ip.src',
          '-Y', combinedFilter
        ], {
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
        });

        // 查询 B: 每个流的 TCP 分析标记
        const { stdout: analysisOut } = await execFileAsync(tsharkPath, [
          '-r', safePcapPath, '-T', 'fields',
          '-e', 'tcp.stream', '-e', 'tcp.analysis.retransmission',
          '-e', 'tcp.analysis.duplicate_ack', '-e', 'tcp.analysis.zero_window',
          '-e', 'tcp.analysis.keep_alive', '-e', 'tcp.analysis.window_update',
          '-Y', combinedFilter
        ], {
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
        });

        // ── Step 3: 解析数据，按流分组 ──
        const streamData = {};
        for (const idx of streamIndices) {
          streamData[idx] = {
            streamIndex: idx,
            synCount: 0, synAckCount: 0, rstCount: 0, finCount: 0, ackCount: 0,
            otherFlags: 0, totalPackets: 0,
            retransmissions: 0, duplicateAcks: 0, zeroWindows: 0,
            keepAlives: 0, windowUpdates: 0,
            hasRst: false, hasFin: false, hasSynAck: false,
            srcIps: new Set(), synSrcIps: new Set(), rstSrcIps: new Set(),
            isUnidirectional: false
          };
        }

        // 解析 flags 数据
        for (const line of flagsOut.split('\n')) {
          if (!line.trim()) continue;
          const [streamStr, flagsHex, srcIp] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx) || !streamData[streamIdx]) continue;
          const sd = streamData[streamIdx];
          sd.totalPackets++;
          sd.srcIps.add(srcIp);

          const hex = parseInt(flagsHex, 16);
          if ((hex & 0x012) === 0x002) { sd.synCount++; sd.synSrcIps.add(srcIp); }        // 纯 SYN（SYN=1, ACK=0）
          if ((hex & 0x012) === 0x012) { sd.synAckCount++; sd.hasSynAck = true; }           // SYN-ACK（SYN=1, ACK=1）
          if (hex & 0x004) { sd.rstCount++; sd.hasRst = true; sd.rstSrcIps.add(srcIp); }
          if (hex & 0x001) { sd.finCount++; sd.hasFin = true; }
          if ((hex & 0x010) && !(hex & 0x002) && !(hex & 0x001) && !(hex & 0x004)) sd.ackCount++;
          if (!(hex & 0x002) && !(hex & 0x012) && !(hex & 0x004) && !(hex & 0x001) && !(hex & 0x010)) sd.otherFlags++;
        }

        // 计算每个流是否为单向捕获
        for (const idx of streamIndices) {
          streamData[idx].isUnidirectional = streamData[idx].srcIps.size === 1;
        }

        // 解析 analysis 数据
        for (const line of analysisOut.split('\n')) {
          if (!line.trim()) continue;
          const parts = line.split('\t');
          const streamIdx = parseInt(parts[0]);
          if (isNaN(streamIdx) || !streamData[streamIdx]) continue;
          const sd = streamData[streamIdx];
          if (parts[1]) sd.retransmissions++;
          if (parts[2]) sd.duplicateAcks++;
          if (parts[3]) sd.zeroWindows++;
          if (parts[4]) sd.keepAlives++;
          if (parts[5]) sd.windowUpdates++;
        }

        // ── Step 4: 问题检测与分类 ──
        const issues = [];

        for (const idx of streamIndices) {
          const sd = streamData[idx];
          const streamIssues = [];

          // 0. 单向流量检测
          if (sd.isUnidirectional) {
            streamIssues.push({
              type: 'UNIDIRECTIONAL_CAPTURE',
              severity: 'info',
              description: `该流仅捕获单向流量(仅来自${[...sd.srcIps].join(', ')}端)，SYN无响应、异常RST断开、四次挥手等需要双向流量判断的检测已跳过。`,
              detail: { srcIps: [...sd.srcIps] }
            });
          }

          // 1. SYN 无响应：有 SYN 但无 SYN-ACK（需双向流量）
          if (sd.synCount > 0 && sd.synAckCount === 0 && !sd.isUnidirectional) {
            streamIssues.push({
              type: 'SYN_NO_RESPONSE',
              severity: 'high',
              description: `发送了 ${sd.synCount} 个SYN包但未收到任何SYN-ACK响应`,
              detail: { synCount: sd.synCount, synAckCount: sd.synAckCount }
            });
          }

          // 2. 端口未开放（RST 拒绝）：有 SYN 且有 RST，且 RST 来自服务端
          if (sd.synCount > 0 && sd.rstCount > 0 && sd.synAckCount === 0) {
            const rstFromServer = [...sd.rstSrcIps].some(ip => !sd.synSrcIps.has(ip));
            if (rstFromServer) {
              streamIssues.push({
                type: 'PORT_CLOSED_RST',
                severity: 'high',
                description: `SYN后收到来自服务端的RST拒绝，目标端口可能未开放`,
                detail: { synCount: sd.synCount, rstCount: sd.rstCount }
              });
            }
          }

          // 3. 客户端 SYN 重传：客户端发送了多个纯 SYN 包
          if (sd.synCount > 1) {
            streamIssues.push({
              type: 'SYN_RETRANSMISSION',
              severity: 'high',
              description: `客户端SYN包重传 ${sd.synCount} 次，可能存在连接超时`,
              detail: { synCount: sd.synCount, synAckCount: sd.synAckCount }
            });
          }

          // 3b. 服务端 SYN-ACK 重传：服务端发送了多个 SYN-ACK 包
          if (sd.synAckCount > 1) {
            streamIssues.push({
              type: 'SYN_ACK_RETRANSMISSION',
              severity: 'high',
              description: `服务端SYN-ACK包重传 ${sd.synAckCount} 次，服务端可能未收到客户端ACK`,
              detail: { synCount: sd.synCount, synAckCount: sd.synAckCount }
            });
          }

          // 4. 超时重传（RTO）
          if (sd.retransmissions > 0) {
            streamIssues.push({
              type: 'RETRANSMISSION',
              severity: sd.retransmissions > 5 ? 'high' : 'medium',
              description: `检测到 ${sd.retransmissions} 次TCP重传`,
              detail: { retransmissions: sd.retransmissions }
            });
          }

          // 5. 零窗口 — 结合 Window Update 判断严重度
          if (sd.zeroWindows > 0) {
            const unrecovered = sd.zeroWindows - sd.windowUpdates;
            if (unrecovered > 0) {
              streamIssues.push({
                type: 'ZERO_WINDOW',
                severity: 'high',
                description: `检测到 ${sd.zeroWindows} 次零窗口，其中 ${unrecovered} 次未恢复（缺少Window Update），接收端可能持续阻塞`,
                detail: { zeroWindows: sd.zeroWindows, windowUpdates: sd.windowUpdates, unrecovered }
              });
            } else {
              streamIssues.push({
                type: 'ZERO_WINDOW',
                severity: 'medium',
                description: `检测到 ${sd.zeroWindows} 次零窗口，均已通过Window Update恢复，可能为瞬时现象`,
                detail: { zeroWindows: sd.zeroWindows, windowUpdates: sd.windowUpdates }
              });
            }
          }

          // 6. 异常 RST 断开：有 RST 但没有正常 FIN 交互（需双向流量 + 连接已建立）
          if (sd.hasRst && !sd.hasFin && !sd.isUnidirectional && sd.synAckCount > 0) {
            streamIssues.push({
              type: 'ABNORMAL_RST',
              severity: 'medium',
              description: `连接已建立(synAckCount=${sd.synAckCount})后被RST强制断开，未经过正常的FIN四次挥手`,
              detail: { rstCount: sd.rstCount, finCount: sd.finCount }
            });
          }

          // 7. 四次挥手不完整：有 FIN 但握手不完整（需双向流量 + ACK回复验证）
          if (sd.hasFin && !sd.isUnidirectional) {
            if (sd.finCount < 2) {
              streamIssues.push({
                type: 'INCOMPLETE_TEARDOWN',
                severity: 'low',
                description: `仅检测到 ${sd.finCount} 个FIN包(四次挥手需要双向各发1个FIN共2个)，挥手可能不完整`,
                detail: { finCount: sd.finCount, ackCount: sd.ackCount }
              });
            } else if (sd.ackCount < 2) {
              streamIssues.push({
                type: 'INCOMPLETE_TEARDOWN',
                severity: 'low',
                description: `检测到${sd.finCount}个FIN包但ACK回复仅${sd.ackCount}个(四次挥手每轮FIN需1个ACK应答)，挥手可能不完整`,
                detail: { finCount: sd.finCount, ackCount: sd.ackCount }
              });
            }
          }

          // 8. 大量重复 ACK（可能丢包）
          if (sd.duplicateAcks > 3) {
            streamIssues.push({
              type: 'DUPLICATE_ACKS',
              severity: 'medium',
              description: `检测到 ${sd.duplicateAcks} 次重复ACK，可能存在丢包`,
              detail: { duplicateAcks: sd.duplicateAcks }
            });
          }

          if (streamIssues.length > 0) {
            issues.push({
              streamIndex: idx,
              packetCount: sd.totalPackets,
              flagsSummary: {
                SYN: sd.synCount, SYN_ACK: sd.synAckCount,
                RST: sd.rstCount, FIN: sd.finCount, ACK: sd.ackCount
              },
              analysisMarkers: {
                retransmissions: sd.retransmissions,
                duplicateAcks: sd.duplicateAcks,
                zeroWindows: sd.zeroWindows,
                keepAlives: sd.keepAlives,
                windowUpdates: sd.windowUpdates
              },
              detectedIssues: streamIssues
            });
          }
        }

        // ── Step 5: SYN Flood 统计检测 ──
        const synOnlyStreams = streamIndices.filter(idx => {
          const sd = streamData[idx];
          return sd.synCount > 0 && sd.synAckCount === 0;
        });
        if (synOnlyStreams.length >= 10) {
          // 统计源 IP 分布
          const { stdout: synIpsOut } = await execFileAsync(tsharkPath, [
            '-r', safePcapPath, '-T', 'fields', '-e', 'ip.src',
            '-Y', `tcp.flags.syn == 1 && tcp.flags.ack == 0 && (${synOnlyStreams.map(n => `tcp.stream eq ${n}`).join(' || ')})`
          ], {
            maxBuffer: 10 * 1024 * 1024,
            env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
          });
          const ipCounts = {};
          for (const ip of synIpsOut.split('\n').map(l => l.trim()).filter(Boolean)) {
            ipCounts[ip] = (ipCounts[ip] || 0) + 1;
          }
          const topIp = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
          issues.push({
            streamIndex: 'SYN_FLOOD_DETECTION',
            packetCount: synOnlyStreams.length,
            flagsSummary: {},
            analysisMarkers: {},
            detectedIssues: [{
              type: 'SYN_FLOOD',
              severity: 'critical',
              description: `检测到 ${synOnlyStreams.length} 个SYN无响应流，疑似SYN Flood攻击`,
              detail: {
                synOnlyStreamCount: synOnlyStreams.length,
                sourceIpDistribution: ipCounts,
                topSourceIp: topIp ? `${topIp[0]} (${topIp[1]} SYNs)` : 'unknown'
              }
            }]
          });
        }

        // ── 构建 JSON 响应 ──
        const result = {
          pcapPath,
          filter: userFilter || null,
          totalStreamsAnalyzed: streamIndices.length,
          streamsWithIssues: issues.length,
          issues,
          summary: issues.length === 0
            ? `分析了 ${streamIndices.length} 个TCP流，未发现四层网络问题。`
            : `分析了 ${streamIndices.length} 个TCP流，发现 ${issues.length} 个流存在问题，共 ${issues.reduce((s, i) => s + i.detectedIssues.length, 0)} 个问题。`
        };

        // 输出截断保护：按比例裁剪 issues 数组，仅截断超出部分
        let jsonOutput = JSON.stringify(result, null, 2);
        const maxChars = 200000;
        if (jsonOutput.length > maxChars) {
          const trimFactor = maxChars / jsonOutput.length;
          const truncatedResult = { ...result };
          truncatedResult.issues = result.issues.slice(0, Math.floor(result.issues.length * trimFactor));
          truncatedResult.summary += ' (输出已截断，部分流详情被省略)';
          jsonOutput = JSON.stringify(truncatedResult, null, 2);
        }

        console.error(`[analyze_l4_network] 分析完成: ${issues.length}/${streamIndices.length} 个流存在问题`);
        return {
          content: [{ type: 'text', text: jsonOutput }],
        };
      } catch (error) {
        console.error(`[analyze_l4_network] 执行错误: ${error.message}`);
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: error.message }, null, 2) }],
          isError: true
        };
      }
    }
  );

  // Tool 10: 分析七层（应用层）网络问题
  server.tool(
    'analyze_l7_network',
    '分析PCAP文件中应用层网络问题。先用tshark过滤命中的数据包，找到关联的TCP流和DNS事务，再逐流/逐事务分析是否存在HTTP 4xx/5xx错误、重定向循环、响应极慢、Content-Length不匹配、服务端提前FIN、DNS查询失败、DNS解析超时等问题。返回JSON格式报告。',
    {
      pcapPath: z.string().describe('待分析的PCAP文件路径，例如：./demo.pcap'),
      tsharkArgs: z.string().describe('tshark命令参数字符串，用于过滤目标数据包。支持 -Y 过滤表达式，例如：-Y "http" 或 -Y "ip.addr == 10.0.0.1"'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapPath, tsharkArgs } = args;
        console.error(`[analyze_l7_network] 开始分析: pcapPath=${pcapPath}, tsharkArgs=${tsharkArgs}`);

        const safePcapPath = await validatePcapPath(pcapPath);
        const parsedArgs = parseTsharkArgs(tsharkArgs);

        // 从用户参数中提取 -Y 过滤器（复用 L4 的安全解析逻辑）
        let userFilter = null;
        const cleanArgs = [];
        for (let i = 0; i < parsedArgs.length; i++) {
          if (parsedArgs[i] === '-Y' || parsedArgs[i] === '--display-filter') {
            userFilter = parsedArgs[i + 1] || null;
            i++;
            continue;
          }
          if (parsedArgs[i] === '-T' || parsedArgs[i] === '-e' || parsedArgs[i] === '-r') {
            i++;
            continue;
          }
          if (parsedArgs[i].startsWith('-T') || parsedArgs[i].startsWith('-e') || parsedArgs[i].startsWith('-r')) continue;
          cleanArgs.push(parsedArgs[i]);
        }

        // ── Step 1: 并行提取 TCP 流编号和 DNS 事务 ID ──
        const getStreamsArgs = ['-r', safePcapPath, '-T', 'fields', '-e', 'tcp.stream'];
        if (userFilter) getStreamsArgs.push('-Y', userFilter);

        const getDnsIdArgs = ['-r', safePcapPath, '-T', 'fields', '-e', 'dns.id'];
        if (userFilter) getDnsIdArgs.push('-Y', userFilter);

        console.error(`[analyze_l7_network] Step1 提取流编号和DNS事务ID`);
        const [{ stdout: streamsOut }, { stdout: dnsIdOut }] = await Promise.all([
          execFileAsync(tsharkPath, getStreamsArgs, {
            maxBuffer: 10 * 1024 * 1024,
            env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
          }),
          execFileAsync(tsharkPath, getDnsIdArgs, {
            maxBuffer: 10 * 1024 * 1024,
            env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
          })
        ]);

        const streamIndices = [...new Set(
          streamsOut.split('\n')
            .map(l => l.trim())
            .filter(l => l !== '' && l !== '_')
            .map(Number)
            .filter(n => !isNaN(n))
        )].sort((a, b) => a - b);

        const dnsIds = [...new Set(
          dnsIdOut.split('\n')
            .map(l => l.trim())
            .filter(l => l !== '')
            .map(Number)
            .filter(n => !isNaN(n))
        )].sort((a, b) => a - b);

        if (streamIndices.length === 0 && dnsIds.length === 0) {
          const result = {
            pcapPath,
            filter: userFilter || null,
            totalStreamsAnalyzed: 0,
            totalDnsTransactionsAnalyzed: 0,
            issues: [],
            summary: '未找到匹配的TCP流或DNS事务，无法进行七层分析。请检查过滤条件或PCAP文件内容。'
          };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        console.error(`[analyze_l7_network] 发现 ${streamIndices.length} 个TCP流, ${dnsIds.length} 个DNS事务`);

        // ── Step 2: 并行批量查询 L7 数据 ──
        const queryPromises = [];

        // 查询 A: HTTP 请求/响应数据（仅在存在TCP流时执行）
        if (streamIndices.length > 0) {
          const streamFilter = streamIndices.map(n => `tcp.stream eq ${n}`).join(' || ');
          const httpFilter = userFilter ? `http && (${streamFilter})` : `http && (${streamFilter})`;
          queryPromises.push(
            execFileAsync(tsharkPath, [
              '-r', safePcapPath, '-T', 'fields',
              '-e', 'tcp.stream', '-e', 'frame.time_epoch',
              '-e', 'http.request.method', '-e', 'http.request.uri',
              '-e', 'http.response.code', '-e', 'http.content_length',
              '-e', 'ip.src',
              '-Y', httpFilter
            ], {
              maxBuffer: 10 * 1024 * 1024,
              env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
            })
          );
          // 查询 C: TCP FIN（HTTP流的服务端提前关闭检测，RST属于L4范畴不在此检测）
          const finFilter = `tcp.flags.fin==1 && (${streamFilter})`;
          queryPromises.push(
            execFileAsync(tsharkPath, [
              '-r', safePcapPath, '-T', 'fields',
              '-e', 'tcp.stream', '-e', 'ip.src', '-e', 'frame.time_epoch',
              '-Y', finFilter
            ], {
              maxBuffer: 10 * 1024 * 1024,
              env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
            })
          );
          // 查询 D: TCP 重传标记（Content-Length不匹配检测辅助）
          const retransFilter = `tcp.analysis.retransmission && (${streamFilter})`;
          queryPromises.push(
            execFileAsync(tsharkPath, [
              '-r', safePcapPath, '-T', 'fields',
              '-e', 'tcp.stream', '-e', 'tcp.analysis.retransmission',
              '-Y', retransFilter
            ], {
              maxBuffer: 10 * 1024 * 1024,
              env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
            })
          );
        }

        // 查询 B: DNS 事务数据（仅在存在DNS事务时执行）
        if (dnsIds.length > 0) {
          const dnsIdFilter = dnsIds.map(n => `dns.id == ${n}`).join(' || ');
          const combinedDnsFilter = userFilter ? `dns && (${dnsIdFilter})` : `dns && (${dnsIdFilter})`;
          queryPromises.push(
            execFileAsync(tsharkPath, [
              '-r', safePcapPath, '-T', 'fields',
              '-e', 'dns.id', '-e', 'frame.time_epoch',
              '-e', 'dns.qry.name', '-e', 'dns.flags.rcode',
              '-e', 'dns.flags.response', '-e', 'dns.time',
              '-Y', combinedDnsFilter
            ], {
              maxBuffer: 10 * 1024 * 1024,
              env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
            })
          );
        }

        const queryResults = await Promise.all(queryPromises);

        // 解包查询结果（根据是否有TCP流和DNS事务确定偏移）
        let httpOut = '', finRstOut = '', retransOut = '', dnsOut = '';
        let resultIdx = 0;
        if (streamIndices.length > 0) {
          httpOut = queryResults[resultIdx++].stdout;
          finRstOut = queryResults[resultIdx++].stdout;
          retransOut = queryResults[resultIdx++].stdout;
        }
        if (dnsIds.length > 0) {
          dnsOut = queryResults[resultIdx].stdout;
        }

        // ── Step 3: 解析数据，按流/事务分组 ──

        // HTTP 流数据
        const httpStreamData = {};
        for (const idx of streamIndices) {
          httpStreamData[idx] = {
            streamIndex: idx,
            packets: [],     // 按时间排序的 HTTP 请求/响应序列
            srcIps: new Set(),
            finEvents: [],   // { time, srcIp }
            hasFin: false,
            retransmissions: 0,
            totalHttpRequests: 0,
            totalHttpResponses: 0
          };
        }

        // 解析 HTTP 请求/响应数据
        for (const line of httpOut.split('\n')) {
          if (!line.trim()) continue;
          const [streamStr, timeStr, method, uri, respCode, contentLength, srcIp] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx) || !httpStreamData[streamIdx]) continue;
          const hd = httpStreamData[streamIdx];
          hd.srcIps.add(srcIp);
          const entry = { time: parseFloat(timeStr), srcIp };
          if (method) {
            entry.type = 'request';
            entry.method = method;
            entry.uri = uri || '';
            hd.totalHttpRequests++;
          } else if (respCode) {
            entry.type = 'response';
            entry.code = parseInt(respCode);
            entry.contentLength = contentLength ? parseInt(contentLength) : null;
            hd.totalHttpResponses++;
          } else {
            continue; // 非 HTTP 请求/响应行，跳过
          }
          hd.packets.push(entry);
        }

        // 按时间排序每个流的 HTTP 包序列
        for (const idx of streamIndices) {
          httpStreamData[idx].packets.sort((a, b) => a.time - b.time);
        }

        // 解析 FIN 数据（含时间戳，用于时序分析）
        for (const line of finRstOut.split('\n')) {
          if (!line.trim()) continue;
          const [streamStr, srcIp, timeStr] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx) || !httpStreamData[streamIdx]) continue;
          const hd = httpStreamData[streamIdx];
          hd.hasFin = true;
          hd.finEvents.push({ time: parseFloat(timeStr) || 0, srcIp });
        }
        // 按 FIN 事件时间排序
        for (const idx of streamIndices) {
          httpStreamData[idx].finEvents.sort((a, b) => a.time - b.time);
        }

        // 解析重传标记
        for (const line of retransOut.split('\n')) {
          if (!line.trim()) continue;
          const [streamStr] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx) || !httpStreamData[streamIdx]) continue;
          httpStreamData[streamIdx].retransmissions++;
        }

        // DNS 事务数据
        const dnsTransData = {};
        for (const id of dnsIds) {
          dnsTransData[id] = {
            dnsId: id,
            queryName: null,
            rcode: null,
            hasQuery: false,
            hasResponse: false,
            queryTime: null,
            responseTime: null,
            dnsTime: null
          };
        }

        for (const line of dnsOut.split('\n')) {
          if (!line.trim()) continue;
          const [idStr, timeStr, qryName, rcode, isResponse, dnsTime] = line.split('\t');
          const dnsId = parseInt(idStr);
          if (isNaN(dnsId) || !dnsTransData[dnsId]) continue;
          const dd = dnsTransData[dnsId];
          if (isResponse === '1') {
            dd.hasResponse = true;
            dd.responseTime = parseFloat(timeStr);
            dd.rcode = rcode ? parseInt(rcode) : 0;
            dd.dnsTime = dnsTime ? parseFloat(dnsTime) : null;
          } else {
            dd.hasQuery = true;
            dd.queryTime = parseFloat(timeStr);
            if (qryName) dd.queryName = qryName;
          }
        }

        // ── Step 4: 问题检测 ──
        const issues = [];

        // HTTP 流检测
        for (const idx of streamIndices) {
          const hd = httpStreamData[idx];
          if (hd.packets.length === 0) continue; // 该流无 HTTP 数据，跳过
          const streamIssues = [];
          const isUnidirectional = hd.srcIps.size === 1;

          // 1. HTTP 4xx 错误
          const codes4xx = hd.packets.filter(p => p.type === 'response' && p.code >= 400 && p.code < 500);
          if (codes4xx.length > 0) {
            streamIssues.push({
              type: 'HTTP_4XX_ERROR',
              severity: 'medium',
              description: `检测到 ${codes4xx.length} 个HTTP 4xx错误响应`,
              detail: { count: codes4xx.length, codes: [...new Set(codes4xx.map(p => p.code))] }
            });
          }

          // 2. HTTP 5xx 错误
          const codes5xx = hd.packets.filter(p => p.type === 'response' && p.code >= 500 && p.code < 600);
          if (codes5xx.length > 0) {
            streamIssues.push({
              type: 'HTTP_5XX_ERROR',
              severity: 'high',
              description: `检测到 ${codes5xx.length} 个HTTP 5xx服务器错误响应`,
              detail: { count: codes5xx.length, codes: [...new Set(codes5xx.map(p => p.code))] }
            });
          }

          // 3. HTTP 重定向循环：同一流内连续出现 ≥3 次 3xx 重定向响应
          if (!isUnidirectional) {
            const respSequence = hd.packets.filter(p => p.type === 'response').map(p => p.code);
            let maxConsecutiveRedirects = 0;
            let currentConsecutive = 0;
            for (const code of respSequence) {
              if (code >= 300 && code < 400) {
                currentConsecutive++;
                if (currentConsecutive > maxConsecutiveRedirects) maxConsecutiveRedirects = currentConsecutive;
              } else {
                currentConsecutive = 0;
              }
            }
            if (maxConsecutiveRedirects >= 3) {
              streamIssues.push({
                type: 'HTTP_REDIRECT_LOOP',
                severity: 'high',
                description: `同一流内连续出现 ${maxConsecutiveRedirects} 次3xx重定向响应，疑似重定向循环`,
                detail: { consecutiveRedirects: maxConsecutiveRedirects }
              });
            }
          }

          // 4. HTTP 响应极慢：请求到响应时间差 > 30s
          if (!isUnidirectional) {
            let maxSlowTime = 0;
            const slowPairs = [];
            // 找每个请求之后的第一个响应
            for (let i = 0; i < hd.packets.length; i++) {
              if (hd.packets[i].type !== 'request') continue;
              const reqTime = hd.packets[i].time;
              // 向后查找最近的响应
              for (let j = i + 1; j < hd.packets.length; j++) {
                if (hd.packets[j].type === 'response') {
                  const elapsed = hd.packets[j].time - reqTime;
                  if (elapsed > 30) {
                    slowPairs.push({ request: hd.packets[i].uri, elapsed: elapsed.toFixed(2) });
                    if (elapsed > maxSlowTime) maxSlowTime = elapsed;
                  }
                  break;
                }
              }
            }
            if (slowPairs.length > 0) {
              streamIssues.push({
                type: 'HTTP_SLOW_RESPONSE',
                severity: 'medium',
                description: `检测到 ${slowPairs.length} 个HTTP响应耗时超过30秒(最长${maxSlowTime.toFixed(2)}秒)`,
                detail: { count: slowPairs.length, maxElapsed: maxSlowTime.toFixed(2), samples: slowPairs.slice(0, 5) }
              });
            }
          }

          // 5. HTTP Content-Length 不匹配：响应声明了 Content-Length 且同流存在重传 + 服务端FIN，响应体可能不完整
          const responsesWithContentLength = hd.packets.filter(p => p.type === 'response' && p.contentLength !== null && p.contentLength > 0);
          if (responsesWithContentLength.length > 0 && hd.retransmissions > 0 && hd.hasFin) {
            streamIssues.push({
              type: 'HTTP_CONTENT_LENGTH_MISMATCH',
              severity: 'high',
              description: `HTTP响应声明了Content-Length但同流存在${hd.retransmissions}次重传且服务端已发FIN，响应体可能不完整`,
              detail: { retransmissions: hd.retransmissions, contentLengthResponses: responsesWithContentLength.length }
            });
          }

          // 6. 服务端提前 FIN：基于时序判断服务端是否在请求未完成时关闭连接
          if (hd.hasFin && !isUnidirectional) {
            // 识别服务端 IP：流中只发送 HTTP 响应的 IP 视为服务端
            const responseSrcIps = new Set(
              hd.packets.filter(p => p.type === 'response').map(p => p.srcIp)
            );
            // 找出服务端发出的 FIN 事件
            const serverFinEvents = hd.finEvents.filter(e => responseSrcIps.has(e.srcIp));
            if (serverFinEvents.length > 0) {
              // 取第一个服务端 FIN 时间点
              const firstFinTime = serverFinEvents[0].time;

              // 基于时序判断：在 FIN 之前发出的请求，如果在 FIN 之后仍未收到响应 → 被中断
              const affectedRequests = [];
              for (let i = 0; i < hd.packets.length; i++) {
                const pkt = hd.packets[i];
                if (pkt.type !== 'request' || pkt.time >= firstFinTime) continue;
                // 向后查找该请求是否在 FIN 之前收到了响应
                let hasResponseBeforeFin = false;
                for (let j = i + 1; j < hd.packets.length; j++) {
                  const next = hd.packets[j];
                  if (next.type === 'response' && next.time < firstFinTime) {
                    hasResponseBeforeFin = true;
                    break;
                  }
                  if (next.time >= firstFinTime) break;
                }
                if (!hasResponseBeforeFin) {
                  affectedRequests.push({ method: pkt.method, uri: pkt.uri, requestTime: pkt.time.toFixed(3) });
                }
              }

              if (affectedRequests.length > 0) {
                const severity = 'high';
                streamIssues.push({
                  type: 'SERVER_PREMATURE_FIN',
                  severity,
                  description: `服务端(${[...responseSrcIps].join(',')})在 ${firstFinTime.toFixed(3)}s 发送FIN，有 ${affectedRequests.length} 个已发出请求未在FIN前收到响应，连接被提前关闭`,
                  detail: {
                    serverIp: [...responseSrcIps],
                    finTime: firstFinTime.toFixed(3),
                    affectedRequestCount: affectedRequests.length,
                    affectedRequests: affectedRequests.slice(0, 10)
                  }
                });
              }
            }
          }

          if (streamIssues.length > 0) {
            issues.push({
              streamIndex: idx,
              protocol: 'HTTP',
              packetCount: hd.packets.length,
              detectedIssues: streamIssues
            });
          }
        }

        // DNS 事务检测
        for (const id of dnsIds) {
          const dd = dnsTransData[id];
          const dnsIssues = [];

          // 7. DNS NXDOMAIN
          if (dd.hasResponse && dd.rcode === 3) {
            dnsIssues.push({
              type: 'DNS_NXDOMAIN',
              severity: 'medium',
              description: `DNS查询 ${dd.queryName || 'unknown'} 返回NXDOMAIN，域名不存在`,
              detail: { queryName: dd.queryName, rcode: dd.rcode }
            });
          }

          // 8. DNS SERVFAIL
          if (dd.hasResponse && dd.rcode === 2) {
            dnsIssues.push({
              type: 'DNS_SERVFAIL',
              severity: 'high',
              description: `DNS查询 ${dd.queryName || 'unknown'} 返回SERVFAIL，DNS服务器故障`,
              detail: { queryName: dd.queryName, rcode: dd.rcode }
            });
          }

          // 9. DNS REFUSED
          if (dd.hasResponse && dd.rcode === 5) {
            dnsIssues.push({
              type: 'DNS_REFUSED',
              severity: 'high',
              description: `DNS查询 ${dd.queryName || 'unknown'} 返回REFUSED，DNS服务器拒绝查询`,
              detail: { queryName: dd.queryName, rcode: dd.rcode }
            });
          }

          // 10. DNS 超时：有查询无响应
          if (dd.hasQuery && !dd.hasResponse) {
            dnsIssues.push({
              type: 'DNS_TIMEOUT',
              severity: 'high',
              description: `DNS查询 ${dd.queryName || 'unknown'} 未收到响应，可能超时`,
              detail: { queryName: dd.queryName, dnsId: dd.dnsId }
            });
          }

          if (dnsIssues.length > 0) {
            issues.push({
              streamIndex: `dns:${id}`,
              protocol: 'DNS',
              packetCount: (dd.hasQuery ? 1 : 0) + (dd.hasResponse ? 1 : 0),
              detectedIssues: dnsIssues
            });
          }
        }

        // ── 构建 JSON 响应 ──
        const result = {
          pcapPath,
          filter: userFilter || null,
          totalStreamsAnalyzed: streamIndices.length,
          totalDnsTransactionsAnalyzed: dnsIds.length,
          streamsWithIssues: issues.length,
          issues,
          summary: issues.length === 0
            ? `分析了 ${streamIndices.length} 个TCP流和 ${dnsIds.length} 个DNS事务，未发现七层网络问题。`
            : `分析了 ${streamIndices.length} 个TCP流和 ${dnsIds.length} 个DNS事务，发现 ${issues.length} 个流/事务存在问题，共 ${issues.reduce((s, i) => s + i.detectedIssues.length, 0)} 个问题。`
        };

        // 输出截断保护：按比例裁剪 issues 数组，仅截断超出部分
        let jsonOutput = JSON.stringify(result, null, 2);
        const maxChars = 200000;
        if (jsonOutput.length > maxChars) {
          const trimFactor = maxChars / jsonOutput.length;
          const truncatedResult = { ...result };
          truncatedResult.issues = result.issues.slice(0, Math.floor(result.issues.length * trimFactor));
          truncatedResult.summary += ' (输出已截断，部分流详情被省略)';
          jsonOutput = JSON.stringify(truncatedResult, null, 2);
        }

        console.error(`[analyze_l7_network] 分析完成: ${issues.length} 个流/事务存在问题`);
        return {
          content: [{ type: 'text', text: jsonOutput }],
        };
      } catch (error) {
        console.error(`[analyze_l7_network] 执行错误: ${error.message}`);
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: error.message }, null, 2) }],
          isError: true
        };
      }
    }
  );
}

// Register prompts with the given server instance
function registerPrompts(server) {
  // Add prompts for each tool
  server.prompt(
  'capture_packets_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the network traffic on interface ${interface} for ${duration} seconds and provide insights about:
1. The types of traffic observed
2. Any notable patterns or anomalies
3. Key IP addresses and ports involved
4. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'summary_stats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please provide a summary of network traffic statistics from interface ${interface} over ${duration} seconds, focusing on:
1. Protocol distribution
2. Traffic volume by protocol
3. Notable patterns in protocol usage
4. Potential network health indicators`
      }
    }]
  })
);

server.prompt(
  'conversations_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze network conversations on interface ${interface} for ${duration} seconds and identify:
1. Most active IP pairs
2. Conversation durations and data volumes
3. Unusual communication patterns
4. Potential indicators of network issues`
      }
    }]
  })
);

server.prompt(
  'check_threats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze traffic on interface ${interface} for ${duration} seconds and check for security threats:
1. Compare captured IPs against URLhaus blacklist
2. Identify potential malicious activity
3. Highlight any concerning patterns
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'check_ip_threats_prompt',
  {
    ip: z.string().describe('IP address to check'),
  },
  ({ ip }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the following IP address (${ip}) for potential security threats:
1. Check against URLhaus blacklist
2. Evaluate the IP's reputation
3. Identify any known malicious activity
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'exec_tshark_prompt',
  {
    pcapPath: z.string().describe('PCAP文件路径'),
    tsharkArgs: z.string().optional().describe('可选的tshark参数提示'),
  },
  ({ pcapPath, tsharkArgs = '' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `【重要提示】当WireMCP的其他内置工具（如analyze_pcap、get_conversations、extract_credentials、check_ip_threats等）无法满足你的分析需求时，再使用exec_tshark工具执行自定义tshark命令。
请分析PCAP文件 ${pcapPath}，需要获取特定数据时：
1. 优先尝试使用WireMCP内置工具，内置工具提供了更优化的输出格式和安全保障
2. 确认内置工具无法满足需求后，使用exec_tshark工具执行自定义tshark命令
3. 常用tshark参数参考示例：
   - 提取HTTP响应内容: -T fields -e http.file_data -Y "http.response" （注意：不要使用data-text-lines，它只返回汇总信息）
   - 提取HTTP请求头: -T fields -e http.request.method -e http.host -e http.user_agent -e http.request.uri
   - 提取DNS查询记录: -T fields -e dns.qry.name -e dns.a -e dns.aaaa
   - 提取SSL/TLS握手信息: -T fields -e ssl.handshake.type -e tls.handshake.extensions_server_name -e tls.cipher_suite
   - 统计协议层级分布: -qz io,phs
   - 显示完整数据包详情: -V -c 1000 （注意：大文件建议配合 -c 限制包数，避免超出缓冲区限制）
4. 常用过滤表达式示例（注意：所有 -Y 后的过滤值必须用引号包裹，特别是包含空格或逻辑运算符时）：
   - 按协议过滤: -Y "http" 或 -Y "dns" 或 -Y "ftp"
   - 按内容匹配过滤: -Y "http.request.uri contains \"flag\""
   - 按IP地址过滤: -Y "ip.addr == 192.168.1.1"
   - 按端口过滤: -Y "tcp.port == 8080"
   - 逻辑与（AND）: -Y "http.request.method == \"GET\" && http.host contains \"example\""
   - 逻辑或（OR）: -Y "tcp.port == 80 || tcp.port == 443"
   - 逻辑非（NOT）: -Y "!(tcp.port == 22)"
   - 组合条件: -Y "ip.addr == 192.168.1.1 && (http.request.method == \"GET\" || http.request.method == \"POST\")"
5. 参数使用注意事项：
   - 包含空格或逻辑运算符（&&、||、!）的 -Y 过滤值必须用引号包裹，否则会被拆分为多个参数导致解析失败
   - 引号格式规则：-Y "过滤表达式"，若表达式内部有引号则转义为 \\"
   - 复杂分析建议分多次执行，避免单次返回数据量过大
   - 如果过滤结果为空，请检查过滤表达式是否正确（可先用 -Y "http" 测试基本过滤是否生效）

${tsharkArgs ? `推荐使用的参数: ${tsharkArgs}` : ''}`
      }
    }]
  })
);

server.prompt(
  'analyze_pcap_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} and provide insights about:
1. Overall traffic patterns
2. Unique IPs and their interactions
3. Protocols and services used
4. Notable events or anomalies
5. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'extract_credentials_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} for potential credential exposure:
1. Look for plaintext credentials (HTTP Basic Auth, FTP, Telnet)
2. Identify Kerberos authentication attempts
3. Extract any hashed credentials
4. Provide security recommendations for credential handling`
      }
    }]
  })
);
}

// Main entry point - supports both STDIO and HTTP transports
async function main() {
  const args = process.argv.slice(2);
  const isHttp = args.includes('--http');
  const portIndex = args.indexOf('--port');
  const port = portIndex !== -1 ? parseInt(args[portIndex + 1]) : 3000;

  if (isHttp) {
    // HTTP mode: Streamable HTTP Transport
    const httpServer = new McpServer({
      name: 'wiremcp',
      version: '1.0.0',
    });
    registerTools(httpServer);
    registerPrompts(httpServer);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
    });
    await httpServer.connect(transport);

    const app = express();
    app.use(express.json());
    app.all('/mcp', async (req, res) => {
      await transport.handleRequest(req, res, req.body);
    });
    app.listen(port, () => {
      console.error(`WireMCP HTTP server listening on http://localhost:${port}/mcp`);
    });
  } else {
    // STDIO mode (default, original behavior)
    const stdioServer = new McpServer({
      name: 'wiremcp',
      version: '1.0.0',
    });
    registerTools(stdioServer);
    registerPrompts(stdioServer);
    await stdioServer.connect(new StdioServerTransport());
    console.error('WireMCP Server is running...');
  }
}

main().catch(err => {
  console.error('Failed to start WireMCP:', err);
  process.exit(1);
});