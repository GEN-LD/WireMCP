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

// Tool 2: Capture and provide summary statistics
server.tool(
  'get_summary_stats',
  'Capture live traffic and provide protocol hierarchy statistics for LLM analysis',
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
      console.error(`Capturing summary stats on ${interface} for ${duration}s`);

      // 【安全修复】使用 execFileAsync 参数数组方式调用，绕过 shell 解析
      await execFileAsync(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', tempPcap, '-qz', 'io,phs'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `Protocol hierarchy statistics for LLM analysis:\n${stdout}`,
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
  'Capture live traffic and provide TCP/UDP conversation statistics for LLM analysis',
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
      console.error(`Capturing conversations on ${interface} for ${duration}s`);

      // 【安全修复】使用 execFileAsync 参数数组方式调用，绕过 shell 解析
      await execFileAsync(
        tsharkPath,
        ['-i', interface, '-w', tempPcap, '-a', `duration:${duration}`],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', tempPcap, '-qz', 'conv,tcp'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `TCP/UDP conversation statistics for LLM analysis:\n${stdout}`,
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

      // 【输出大小限制】防止超大数据量导致LLM上下文溢出，超过720K字符时自动截断
      const maxChars = 720000;
      let output = stdout;
      if (output.length > maxChars) {
        output = output.slice(0, maxChars) + '\n... [输出已截断，数据量超过上下文限制]';
        console.error(`输出已从 ${stdout.length} 字符截断到 ${maxChars} 字符`);
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