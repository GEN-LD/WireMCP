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
// 【安全修复】将 promisify 的底层从 exec 改为 execFile，保证所有调用点使用安全的参数传递方式
const execFileAsync = promisify(execFile);
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const express = require('express');
const multer = require('multer');

// Redirect console.log to stderr
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);

// 【安全修复】输入白名单校验函数，防止攻击者通过恶意输入构造 shell 注入载荷
// 在所有使用用户输入调用系统命令之前，必须先经过这些校验函数

/**
 * 通过 user_id + session_id + fileName 解析上传文件的绝对路径
 * 三重安全校验：
 *   1. user_id/session_id 正则校验（仅字母数字下划线连字符，从根本上阻断路径穿越）
 *   2. path.basename(fileName) 剥离任何目录部分，防止 "../../etc/passwd" 类路径穿越
 *   3. 扩展名白名单校验
 * @param {string} fileName - 文件名（仅文件名，不含路径）
 * @param {string} userId - 用户 ID
 * @param {string} sessionId - 会话 ID
 * @param {string[]} allowedExts - 允许的扩展名白名单
 * @returns {Promise<string>} 安全的绝对路径
 */
async function resolveUploadPath(fileName, userId, sessionId, allowedExts) {
  validateUserId(userId);
  validateSessionId(sessionId);

  if (typeof fileName !== 'string' || !fileName) {
    throw new Error('文件名不能为空。');
  }

  const safeFileName = path.basename(fileName);
  const ext = path.extname(safeFileName).toLowerCase();
  if (!allowedExts.includes(ext)) {
    throw new Error(
      `不支持的文件扩展名: "${ext}"。仅允许: ${allowedExts.join(', ')}`
    );
  }

  const resolved = path.join(UPLOAD_BASE_DIR, userId, sessionId, safeFileName);
  try {
    await fs.access(resolved);
  } catch {
    throw new Error(
      `文件不存在: ${safeFileName} (user_id=${userId}, session_id=${sessionId})。` +
      `请先通过 POST /mcp/upload 上传该文件。`
    );
  }
  return resolved;
}

/**
 * 校验上传请求的 user_id
 * 仅允许字母、数字、下划线、连字符，长度 1~128
 * 正则已排除 "."、"/"、"\\"、空字符等，从根本上阻断路径穿越
 */
function validateUserId(id) {
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) {
    throw new Error(`Invalid user_id: "${id}". Only letters, digits, underscore and hyphen are allowed, length 1-128.`);
  }
  return id;
}

/**
 * 校验上传请求的 session_id
 * 规则同 user_id
 */
function validateSessionId(id) {
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) {
    throw new Error(`Invalid session_id: "${id}". Only letters, digits, underscore and hyphen are allowed, length 1-128.`);
  }
  return id;
}

/**
 * 净化上传文件名并校验扩展名白名单
 * path.basename 剥离任何目录部分，防止 "../../etc/passwd" 类路径穿越攻击
 * @param {string} originalname - 客户端提供的原始文件名
 * @returns {{ filename: string, ext: string }} 净化后的文件名与小写扩展名
 */
function sanitizeUploadFilename(originalname) {
  if (typeof originalname !== 'string' || !originalname) {
    throw new Error('Missing upload filename.');
  }
  const filename = path.basename(originalname);
  const ext = path.extname(filename).toLowerCase();
  if (!UPLOAD_ALLOWED_EXTENSIONS.includes(ext)) {
    throw new Error(
      `Unsupported file extension: "${ext}". Allowed extensions: ${UPLOAD_ALLOWED_EXTENSIONS.join(', ')}`
    );
  }
  return { filename, ext };
}

// 上传文件配置
const UPLOAD_BASE_DIR = path.join(__dirname, 'uploads');
const UPLOAD_TMP_DIR = path.join(UPLOAD_BASE_DIR, '.tmp');
const UPLOAD_MAX_SIZE = 100 * 1024 * 1024;
const UPLOAD_ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap', '.txt', '.log'];
const PCAP_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];
const KEYLOG_EXTENSIONS = ['.txt', '.log'];

/**
 * 文件上传 multer 实例
 * 采用"先写临时目录、校验通过后再移动"的两阶段策略：
 *   1. multer 先将文件写入项目内临时目录（与目标目录同盘，避免跨盘 rename 触发 EXDEV）
 *   2. 路由处理器校验 user_id/session_id/扩展名通过后，再移动到 user_id/session_id 目录
 * 这样即便 multipart 中文本字段出现在文件字段之后，也能可靠完成校验
 */
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      fs.mkdir(UPLOAD_TMP_DIR, { recursive: true })
        .then(() => cb(null, UPLOAD_TMP_DIR))
        .catch(err => cb(err));
    },
    filename: (req, file, cb) => {
      cb(null, `wiremcp_upload_${crypto.randomUUID()}`);
    }
  }),
  limits: { fileSize: UPLOAD_MAX_SIZE }
});

/**
 * 包裹 upload.single('file')，将 multer 错误（如超限）转为 JSON 响应而非透传给默认错误处理器
 */
const uploadSingleFile = (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          success: false,
          error: `文件大小超过上限（${UPLOAD_MAX_SIZE / 1024 / 1024}MB）。`
        });
      }
      return res.status(400).json({ success: false, error: err.message });
    }
    next();
  });
};

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
// 分批查询阈值：单次 tshark 调用最多包含的流/事务数量，避免 spawn E2BIG（ARGS 超长）
const MAX_BATCH_SIZE = 200;

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
        'PCAP 文件已通过 pcapFileName + user_id + session_id 参数定位，无需在 tsharkArgs 中重复设置 -r',
        '如需分析多个文件，请多次调用 exec_tshark 工具，每次指定不同 pcapFileName',
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
    // 【安全拦截】-o 参数允许设置tshark偏好，但禁止加载Lua脚本等危险偏好
    if (args[i] === '-o' || args[i] === '--override-prefs') {
      if (i + 1 < args.length) {
        const prefValue = args[i + 1];
        if (typeof prefValue === 'string' && /\blua\b/i.test(prefValue)) {
          throw new Error(
            `【安全拦截】检测到 -o 参数试图设置Lua相关偏好 "${prefValue}"。\n` +
            `风险说明：-o lua.* 可加载Lua脚本，存在代码执行风险。\n` +
            `请移除Lua相关偏好设置，或使用其他合法参数完成分析。`
          );
        }
      }
    }
  }
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
// Tool 2: Analyze a PCAP file and provide protocol hierarchy statistics
server.tool(
  'get_summary_stats',
  'Analyze a PCAP file and provide protocol hierarchy statistics for LLM analysis',
  {
    pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
    user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
    session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapFileName, user_id, session_id } = args;
      console.error(`Analyzing summary stats for PCAP: ${pcapFileName} (user=${user_id}, session=${session_id})`);

      const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);

      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        ['-r', safePcapPath, '-qz', 'io,phs'],
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      return {
        content: [{
          type: 'text',
          text: `Analyzed PCAP: ${pcapFileName}\n\nProtocol hierarchy statistics:\n${stdout}`,
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
    pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
    user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
    session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapFileName, user_id, session_id } = args;
      console.error(`Analyzing conversations in PCAP: ${pcapFileName} (user=${user_id}, session=${session_id})`);

      const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);

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
    pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
    user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
    session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
    tsharkArgs: z.string().describe('tshark命令参数字符串，必须用引号包裹。如果参数内部也包含引号，需要转义。示例："-T fields -e http.host -Y \\"http.request.uri contains \\\\\\"flag\\\\\\"\\""。注意：所有包含空格或逻辑运算符（&&、||、!）的 -Y 过滤值都必须用引号包裹，例如：-Y \\"tcp.port == 80 && http.request.method == GET\\"'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapFileName, user_id, session_id, tsharkArgs } = args;
      console.error(`执行自定义tshark命令: ${tsharkArgs}`);
      console.error(`分析PCAP文件: ${pcapFileName} (user=${user_id}, session=${session_id})`);

      const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);

      const argsArray = parseTsharkArgs(tsharkArgs);

      validateTsharkArgs(argsArray);

      const fullArgs = ['-r', safePcapPath, ...argsArray];

      const { stdout, stderr } = await execFileAsync(
        tsharkPath,
        fullArgs,
        {
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
        }
      );
      if (stderr) console.error(`tshark标准错误输出: ${stderr}`);

      let output = decodeHexFields(stdout);

      const command = `tshark -r ${pcapFileName} ${tsharkArgs}`;
      const result = {
        pcapFileName,
        user_id,
        session_id,
        command,
        output,
        truncated: false,
        analysisPrompt: [
          `你执行了自定义tshark命令: ${command}`,
          '请根据上述output字段中的输出数据进行网络流量分析：',
          '  - 识别异常通信模式（如异常连接频率、非标准端口通信、可疑IP地址）',
          '  - 分析协议特征（如异常协议使用、畸形请求/响应）',
          '  - 检测敏感信息泄露（如明文密码、令牌、内部路径）',
          '  - 发现安全攻击行为（如扫描探测、注入尝试、C2通信）',
          output.trim() === ''
            ? '注意：tshark输出为空，可能过滤条件过严或无匹配数据包，请检查过滤表达式是否正确。'
            : null
        ].filter(Boolean).join('\n')
      };

      // 【输出截断保护】参考 analyze_l4/l7 截断模式，按比例裁剪output字符串
      let jsonOutput = JSON.stringify(result, null, 2);
      const maxChars = 200000;
      if (jsonOutput.length > maxChars) {
        const trimFactor = maxChars / jsonOutput.length;
        const truncatedResult = { ...result };
        truncatedResult.output = result.output.slice(0, Math.floor(result.output.length * trimFactor));
        truncatedResult.truncated = true;
        truncatedResult.originalLength = result.output.length;
        truncatedResult.analysisPrompt += ' (原始输出已截断，仅保留部分内容，建议缩小过滤范围以获取完整数据)';
        jsonOutput = JSON.stringify(truncatedResult, null, 2);
        console.error(`exec_tshark输出已从 ${result.output.length} 字符按比例截断到 ${truncatedResult.output.length} 字符`);
      }

      return {
        content: [{ type: 'text', text: jsonOutput }],
      };
    } catch (error) {
      console.error(`exec_tshark执行错误: ${error.message}`);
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: error.message }, null, 2) }],
        isError: true
      };
    }
  }
);

// Tool 7: Analyze an existing PCAP file for general context
server.tool(
  'analyze_pcap',
  'Analyze a PCAP file and provide general packet data as JSON for LLM analysis',
  {
    pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
    user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
    session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapFileName, user_id, session_id } = args;
      console.error(`Analyzing PCAP file: ${pcapFileName} (user=${user_id}, session=${session_id})`);

      const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);
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

      const outputText = `Analyzed PCAP: ${pcapFileName}\n\n` +
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
      pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
      user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
      session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapFileName, user_id, session_id } = args;
        console.error(`Extracting credentials from PCAP file: ${pcapFileName} (user=${user_id}, session=${session_id})`);
  
        const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);
  
        const { stdout: plaintextOut } = await execFileAsync(
          tsharkPath,
          ['-r', safePcapPath, '-T', 'fields', '-e', 'http.authbasic', '-e', 'ftp.request.command', '-e', 'ftp.request.arg', '-e', 'telnet.data', '-e', 'frame.number'],
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

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

      const outputText = `Analyzed PCAP: ${pcapFileName}\n\n` +
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
      pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
      user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
      session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
      tsharkArgs: z.string().describe('tshark命令参数字符串，用于过滤目标数据包。支持 -Y 过滤表达式，例如：-Y "http" 或 -Y "ip.addr == 10.0.0.1"'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapFileName, user_id, session_id, tsharkArgs } = args;
        console.error(`[analyze_l4_network] 开始分析: pcapFileName=${pcapFileName}, user=${user_id}, session=${session_id}, tsharkArgs=${tsharkArgs}`);

        const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);
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
            pcapFileName,
            user_id,
            session_id,
            filter: userFilter || null,
            totalStreams: 0,
            issues: [],
            summary: '未找到匹配的TCP流，无法进行四层分析。请检查过滤条件或PCAP文件内容。'
          };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        console.error(`[analyze_l4_network] 发现 ${streamIndices.length} 个TCP流: [${streamIndices.join(', ')}]`);

        // ── Step 2: 逐流批量查询（分批避免流过多导致 spawn E2BIG）──
        const l4Env = { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` };
        let flagsOut = '';
        let analysisOut = '';

        for (let bi = 0; bi < streamIndices.length; bi += MAX_BATCH_SIZE) {
          const batch = streamIndices.slice(bi, bi + MAX_BATCH_SIZE);
          const streamFilter = batch.map(n => `tcp.stream eq ${n}`).join(' || ');
          const batchFilter = userFilter ? `(${userFilter}) && (${streamFilter})` : streamFilter;

          // 查询 A: 每个流的 TCP flags 汇总
          const { stdout: fOut } = await execFileAsync(tsharkPath, [
            '-r', safePcapPath, '-T', 'fields',
            '-e', 'tcp.stream', '-e', 'tcp.flags', '-e', 'ip.src',
            '-Y', batchFilter
          ], {
            maxBuffer: 10 * 1024 * 1024,
            env: l4Env
          });
          flagsOut += (flagsOut ? '\n' : '') + fOut;

          // 查询 B: 每个流的 TCP 分析标记
          const { stdout: aOut } = await execFileAsync(tsharkPath, [
            '-r', safePcapPath, '-T', 'fields',
            '-e', 'tcp.stream', '-e', 'tcp.analysis.retransmission',
            '-e', 'tcp.analysis.duplicate_ack', '-e', 'tcp.analysis.zero_window',
            '-e', 'tcp.analysis.keep_alive', '-e', 'tcp.analysis.window_update',
            '-Y', batchFilter
          ], {
            maxBuffer: 10 * 1024 * 1024,
            env: l4Env
          });
          analysisOut += (analysisOut ? '\n' : '') + aOut;
        }

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
          pcapFileName,
          user_id,
          session_id,
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
      pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
      user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
      session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
      tsharkArgs: z.string().describe('tshark命令参数字符串，用于过滤目标数据包。支持 -Y 过滤表达式，例如：-Y "http" 或 -Y "ip.addr == 10.0.0.1"'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapFileName, user_id, session_id, tsharkArgs } = args;
        console.error(`[analyze_l7_network] 开始分析: pcapFileName=${pcapFileName}, user=${user_id}, session=${session_id}, tsharkArgs=${tsharkArgs}`);

        const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);
        const parsedArgs = parseTsharkArgs(tsharkArgs);

        // 从用户参数中提取 -Y 过滤器（复用 L4 的安全解析逻辑）
        // 注意：-T、-e、-r 等格式/字段参数与工具自身的硬编码查询不兼容，直接跳过
        let userFilter = null;
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
            pcapFileName,
            user_id,
            session_id,
            filter: userFilter || null,
            totalStreamsAnalyzed: 0,
            totalDnsTransactionsAnalyzed: 0,
            issues: [],
            summary: '未找到匹配的TCP流或DNS事务，无法进行七层分析。请检查过滤条件或PCAP文件内容。'
          };
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        console.error(`[analyze_l7_network] 发现 ${streamIndices.length} 个TCP流, ${dnsIds.length} 个DNS事务`);

        // ── Step 2: 并行批量查询 ──
        const queryPromises = [];

        // TCP: 分批查询 — 避免流过多导致 spawn E2BIG
        if (streamIndices.length > 0) {
          const l7Env = { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` };
          queryPromises.push(
            (async () => {
              let allOut = '';
              for (let bi = 0; bi < streamIndices.length; bi += MAX_BATCH_SIZE) {
                const batch = streamIndices.slice(bi, bi + MAX_BATCH_SIZE);
                const tcpFilter = batch.map(n => `tcp.stream eq ${n}`).join(' || ');
                const { stdout } = await execFileAsync(tsharkPath, [
                  '-r', safePcapPath, '-T', 'fields',
                  '-e', 'tcp.stream', '-e', 'tcp.flags', '-e', 'ip.src',
                  '-e', 'frame.time_epoch',
                  '-e', 'http.request.method', '-e', 'http.request.uri',
                  '-e', 'http.response.code', '-e', 'http.content_length',
                  '-e', 'tcp.analysis.retransmission',
                  '-Y', tcpFilter
                ], {
                  maxBuffer: 10 * 1024 * 1024,
                  env: l7Env
                });
                allOut += (allOut ? '\n' : '') + stdout;
              }
              return { stdout: allOut };
            })()
          );
        }

        // DNS: 分批查询 — 避免DNS事务过多导致 spawn E2BIG
        if (dnsIds.length > 0) {
          const l7Env = { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` };
          queryPromises.push(
            (async () => {
              let allOut = '';
              for (let bi = 0; bi < dnsIds.length; bi += MAX_BATCH_SIZE) {
                const batch = dnsIds.slice(bi, bi + MAX_BATCH_SIZE);
                const dnsIdFilter = batch.map(n => `dns.id == ${n}`).join(' || ');
                const combinedDnsFilter = `dns && (${dnsIdFilter})`;
                const { stdout } = await execFileAsync(tsharkPath, [
                  '-r', safePcapPath, '-T', 'fields',
                  '-e', 'dns.id', '-e', 'frame.time_epoch',
                  '-e', 'dns.qry.name', '-e', 'dns.flags.rcode',
                  '-e', 'dns.flags.response', '-e', 'dns.time',
                  '-Y', combinedDnsFilter
                ], {
                  maxBuffer: 10 * 1024 * 1024,
                  env: l7Env
                });
                allOut += (allOut ? '\n' : '') + stdout;
              }
              return { stdout: allOut };
            })()
          );
        }

        // TLS: 查询TLS握手流和TLS Application Data（用于辅助判断提前FIN误报）
        // 查询A：哪些TCP流包含TLS握手
        const tlsHandshakePromise = execFileAsync(tsharkPath, [
          '-r', safePcapPath, '-T', 'fields',
          '-e', 'tcp.stream',
          '-Y', 'tls.handshake'
        ], {
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` }
        });

        // 查询B：TLS Application Data包（先发查询A获取TLS流列表，再构建流过滤）
        const { stdout: tlsHandshakeOut } = await tlsHandshakePromise;
        const tlsStreamSet = new Set(
          tlsHandshakeOut.split('\n')
            .map(l => l.trim())
            .filter(l => l !== '' && l !== '_')
            .map(Number)
            .filter(n => !isNaN(n))
        );
        const tlsStreamIndices = [...tlsStreamSet].sort((a, b) => a - b);
        const tlsStreamFiltered = tlsStreamIndices.filter(n => streamIndices.includes(n));
        let hasTlsQuery = false;
        if (tlsStreamFiltered.length > 0) {
          hasTlsQuery = true;
          const l7Env = { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` };
          queryPromises.push(
            (async () => {
              let allOut = '';
              for (let bi = 0; bi < tlsStreamFiltered.length; bi += MAX_BATCH_SIZE) {
                const batch = tlsStreamFiltered.slice(bi, bi + MAX_BATCH_SIZE);
                const tlsAppDataFilter = batch.map(n => `tcp.stream eq ${n}`).join(' || ');
                const { stdout } = await execFileAsync(tsharkPath, [
                  '-r', safePcapPath, '-T', 'fields',
                  '-e', 'tcp.stream', '-e', 'frame.time_epoch', '-e', 'ip.src',
                  '-Y', `tls.app_data && (${tlsAppDataFilter})`
                ], {
                  maxBuffer: 10 * 1024 * 1024,
                  env: l7Env
                });
                allOut += (allOut ? '\n' : '') + stdout;
              }
              return { stdout: allOut };
            })()
          );
        }

        const queryResults = await Promise.all(queryPromises);

        // 解包：根据是否有TCP流、DNS事务、TLS查询确定顺序
        // 入队顺序：TCP(可选) → DNS(可选) → TLS App Data(可选)
        let tcpOut = '', dnsOut = '', tlsAppDataOut = '';
        let resultIdx = 0;
        if (streamIndices.length > 0) tcpOut = queryResults[resultIdx++].stdout;
        if (dnsIds.length > 0) dnsOut = queryResults[resultIdx++].stdout;
        if (hasTlsQuery) tlsAppDataOut = queryResults[resultIdx++].stdout;

        // ── Step 3: 解析数据，按流/事务分组 ──

        // TCP 流数据（包含流内所有包：TCP控制包 + HTTP应用包）
        const streamData = {};
        for (const idx of streamIndices) {
          streamData[idx] = {
            streamIndex: idx,
            packets: [],     // 流内所有 TCP 包（按时间排序）
            srcIps: new Set(),
            finEvents: [],   // { time, srcIp }，从 tcp.flags hex 提取
            rstEvents: [],   // { time, srcIp }，从 tcp.flags hex 提取
            hasFin: false,
            retransmissions: 0,
            totalHttpRequests: 0,
            totalHttpResponses: 0,
            isTls: false,              // 该流是否存在 TLS 握手
            tlsAppDataEvents: []       // [{ time, srcIp }] 加密的 TLS 应用数据
          };
        }

        // 统一解析：单次遍历完成 TCP flags / HTTP / 重传 的提取
        for (const line of tcpOut.split(/\r?\n/)) {
          if (!line.trim()) continue;
          const [streamStr, flagsHex, srcIp, timeStr,
                 method, uri, respCode, contentLength, retrans] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx) || !streamData[streamIdx]) continue;
          const sd = streamData[streamIdx];
          sd.srcIps.add(srcIp);

          const entry = {
            time: parseFloat(timeStr),
            srcIp,
            isRetransmission: !!retrans
          };

          // 从 tcp.flags hex 提取 FIN、RST 和 ACK（FIN=0x001, RST=0x004, ACK=0x010）
          if (flagsHex) {
            const hex = parseInt(flagsHex, 16);
            if (!isNaN(hex)) {
              if (hex & 0x001) {
                sd.hasFin = true;
                sd.finEvents.push({ time: entry.time, srcIp });
              }
              if (hex & 0x004) {
                sd.rstEvents.push({ time: entry.time, srcIp });
              }
              if (hex & 0x010) {
                entry.hasAck = true;
              }
            }
          }

          // 重传计数
          if (retrans) sd.retransmissions++;

          // HTTP 层分类
          if (method) {
            entry.type = 'request';
            entry.method = method;
            entry.uri = uri || '';
            sd.totalHttpRequests++;
          } else if (respCode) {
            entry.type = 'response';
            entry.code = parseInt(respCode);
            entry.contentLength = contentLength ? parseInt(contentLength) : null;
            sd.totalHttpResponses++;
          }
          // 非HTTP包不设 type，检测逻辑通过 p.type 过滤自然跳过

          sd.packets.push(entry);
        }

        // 按时间排序每个流的包序列和FIN事件
        for (const idx of streamIndices) {
          streamData[idx].packets.sort((a, b) => a.time - b.time);
          streamData[idx].finEvents.sort((a, b) => a.time - b.time);
        }

        // 解析 TLS 握手结果：标记哪些 TCP 流包含 TLS 握手
        for (const idx of tlsStreamFiltered) {
          if (streamData[idx]) {
            streamData[idx].isTls = true;
          }
        }
        console.error(`[analyze_l7_network] TLS握手流: ${tlsStreamFiltered.length}个 (命中过滤的: ${tlsStreamFiltered.length})`);

        // 解析 TLS Application Data：按流分组存储加密应用数据事件
        let tlsAppDataCount = 0;
        for (const line of tlsAppDataOut.split(/\r?\n/)) {
          if (!line.trim()) continue;
          const [streamStr, timeStr, srcIp] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx) || !streamData[streamIdx]) continue;
          streamData[streamIdx].tlsAppDataEvents.push({
            time: parseFloat(timeStr),
            srcIp
          });
          tlsAppDataCount++;
        }
        // 对 TLS App Data 事件也按时间排序
        for (const idx of streamIndices) {
          streamData[idx].tlsAppDataEvents.sort((a, b) => a.time - b.time);
        }
        console.error(`[analyze_l7_network] TLS Application Data包: ${tlsAppDataCount}个`);

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

        for (const line of dnsOut.split(/\r?\n/)) {
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
          const hd = streamData[idx];
          if (hd.totalHttpRequests === 0 && hd.totalHttpResponses === 0) continue; // 该流无 HTTP 数据，跳过
          const streamIssues = [];
          // 综合HTTP层数据和FIN事件判断是否单向流量
          // 仅用HTTP包的srcIps会有缺陷：当服务端无HTTP响应时，srcIps只有客户端IP，被误判为单向
          // 补充FIN事件的IP：如果FIN来自不同IP，说明是双向TCP流
          const allKnownIps = new Set(hd.srcIps);
          for (const fe of hd.finEvents) allKnownIps.add(fe.srcIp);
          const isUnidirectional = allKnownIps.size === 1;

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

          // 6. HTTP请求无响应检测：统一检测请求发出后未收到响应的情况
          //    根据是否存在服务端FIN，区分为两种子类型：
          //    - SERVER_PREMATURE_FIN：服务端在请求未完成时发FIN关闭连接
          //    - HTTP_REQUEST_NO_RESPONSE：请求无响应且无服务端FIN（如NAT超时、服务端崩溃等）
          if (!isUnidirectional) {
            // 识别服务端 IP：
            // 优先：流中发送 HTTP 响应的 IP 视为服务端
            // 退化：若无 HTTP 响应（如服务端直接FIN无响应），则FIN来源中非客户端请求IP的视为服务端
            const requestSrcIps = new Set(
              hd.packets.filter(p => p.type === 'request').map(p => p.srcIp)
            );
            const responseSrcIps = new Set(
              hd.packets.filter(p => p.type === 'response').map(p => p.srcIp)
            );
            // 如果有HTTP响应，响应方就是服务端；否则FIN来源中非请求方的IP视为服务端
            let serverIps = responseSrcIps;
            if (serverIps.size === 0 && hd.hasFin) {
              serverIps = new Set(
                hd.finEvents.filter(e => !requestSrcIps.has(e.srcIp)).map(e => e.srcIp)
              );
            }
            // 找出服务端发出的 FIN 事件
            const serverFinEvents = hd.hasFin
              ? hd.finEvents.filter(e => serverIps.has(e.srcIp))
              : [];
            const firstFinTime = serverFinEvents.length > 0 ? serverFinEvents[0].time : null;

            // 使用FIFO队列进行请求-响应配对
            // HTTP在同一TCP流中严格按序响应，因此第一个响应匹配最早未匹配的请求
            const pendingRequests = [];  // 未匹配的请求队列
            const prematureFinRequests = [];  // 有FIN：服务端未响应完毕就发FIN
            const noResponseRequests = [];    // 无FIN：请求无响应

            for (const pkt of hd.packets) {
              // 服务端FIN之后的请求，直接归入无响应
              // 注意：用 > 而非 >=，因为FIN包本身可能携带最后一个HTTP响应（常见于HTTP/1.1 Connection: close）
              if (firstFinTime !== null && pkt.time > firstFinTime) {
                if (pkt.type === 'request') {
                  noResponseRequests.push({ method: pkt.method, uri: pkt.uri, requestTime: pkt.time.toFixed(3) });
                }
                continue;
              }

              if (pkt.type === 'request') {
                pendingRequests.push({ method: pkt.method, uri: pkt.uri, requestTime: pkt.time.toFixed(3) });
              } else if (pkt.type === 'response') {
                // FIFO：响应对应最早未匹配的请求
                if (pendingRequests.length > 0) {
                  pendingRequests.shift();
                }
              }
            }

            // FIN前仍未匹配的请求：服务端未响应完毕就发FIN
            if (firstFinTime !== null) {
              prematureFinRequests.push(...pendingRequests);
            } else {
              // 无FIN时：未匹配的请求归入无响应
              noResponseRequests.push(...pendingRequests);
            }

            // 过滤 TLS 流中的误报：同时满足以下三个条件才不计入提前FIN告警
            // 条件1: 请求基于 TLS 的 HTTP 请求
            // 条件2: 未看到对应的 HTTP 响应（已在 pendingRequests 中）
            // 条件3: 客户端发 HTTP 请求后，服务端回完 ACK，紧跟着回 TLS Application Data
            // 这种情况说明服务端确实响应了，只是响应为密文未能解密，不应报提前FIN
            const tlsUndecryptedRequests = [];
            if (hd.isTls && firstFinTime !== null && prematureFinRequests.length > 0) {
              prematureFinRequests = prematureFinRequests.filter(req => {
                const reqTime = parseFloat(req.requestTime);
                // 检查服务端是否在请求后、FIN前发送了 TLS Application Data
                const serverAppDataAfterReq = hd.tlsAppDataEvents.filter(e =>
                  serverIps.has(e.srcIp) && e.time > reqTime && e.time < firstFinTime
                );
                if (serverAppDataAfterReq.length === 0) {
                  return true; // 无加密数据，保持为提前FIN
                }
                // 进一步检查：请求后服务端是否回了 ACK（纯TCP ACK包，非HTTP数据）
                const serverAckAfterReq = hd.packets.some(p =>
                  serverIps.has(p.srcIp) &&
                  p.hasAck &&
                  !p.type &&
                  p.time > reqTime &&
                  p.time < serverAppDataAfterReq[0].time
                );
                if (serverAckAfterReq) {
                  // 三个条件都满足：响应可能为密文未解密，不计入提前FIN
                  tlsUndecryptedRequests.push(req);
                  return false;
                }
                return true; // 无ACK确认，仍保留在提前FIN
              });
            }

            // 报告服务端提前FIN
            if (prematureFinRequests.length > 0) {
              streamIssues.push({
                type: 'SERVER_PREMATURE_FIN',
                severity: 'high',
                description: `服务端(${[...serverIps].join(',')})在 ${firstFinTime.toFixed(3)}s 发送FIN，有 ${prematureFinRequests.length} 个已发出请求未在FIN前收到响应，连接被提前关闭`,
                detail: {
                  serverIp: [...serverIps],
                  finTime: firstFinTime.toFixed(3),
                  affectedRequestCount: prematureFinRequests.length,
                  affectedRequests: prematureFinRequests.slice(0, 10)
                }
              });
            }

            // 报告 TLS 响应疑似未解密（不计入提前FIN，但提醒用户可能存在解密失败）
            if (tlsUndecryptedRequests.length > 0) {
              streamIssues.push({
                type: 'TLS_DECRYPT_PARTIAL',
                severity: 'medium',
                description: `检测到 ${tlsUndecryptedRequests.length} 个基于TLS的HTTP请求，服务端在ACK后回复了TLS Application Data（加密响应数据），但未解密出HTTP响应。可能原因：响应数据过大、TCP乱序/重传导致解密失败等。建议重新抓包或使用高版本tshark/wireshark重试解密。`,
                detail: {
                  serverIp: [...serverIps],
                  finTime: firstFinTime.toFixed(3),
                  affectedRequestCount: tlsUndecryptedRequests.length,
                  affectedRequests: tlsUndecryptedRequests.slice(0, 10)
                }
              });
            }

            // 报告请求无响应（无服务端FIN）
            // 注意：如果服务端发了RST，L4分析工具已覆盖此场景，L7不再重复告警
            const hasServerRst = serverIps.size > 0 &&
              hd.rstEvents.some(e => serverIps.has(e.srcIp));
            if (noResponseRequests.length > 0 && !hasServerRst) {
              streamIssues.push({
                type: 'HTTP_REQUEST_NO_RESPONSE',
                severity: 'medium',
                description: `检测到 ${noResponseRequests.length} 个HTTP请求未收到响应且无服务端FIN，可能原因：服务端崩溃、NAT超时、中间设备丢包等`,
                detail: {
                  affectedRequestCount: noResponseRequests.length,
                  affectedRequests: noResponseRequests.slice(0, 10)
                }
              });
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
          pcapFileName,
          user_id,
          session_id,
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

  // Tool 11: SSL/TLS 解密分析
  server.tool(
    'analyze_ssl_tls',
    '解密分析SSL/TLS流量：分析TLS握手安全信息（弱版本、弱密码等），并使用SSLKEYLOGFILE解密流量，分析获取HTTP明文内容（请求行为、响应摘要），检测4xx/5xx、重定向循环、响应过慢等HTTP问题。返回JSON格式报告。',
    {
      pcapFileName: z.string().describe('待分析的PCAP文件名称（仅文件名，不含路径），例如：demo.pcap'),
      keylogFileName: z.string().describe('SSLKEYLOGFILE文件名称（仅文件名，不含路径），例如：sslkeylog.txt'),
      user_id: z.string().describe('用户ID（仅字母、数字、下划线、连字符）'),
      session_id: z.string().describe('会话ID（仅字母、数字、下划线、连字符）'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapFileName, keylogFileName, user_id, session_id } = args;
        console.error(`[analyze_ssl_tls] 开始分析: pcapFileName=${pcapFileName}, keylogFileName=${keylogFileName}, user=${user_id}, session=${session_id}`);

        const safePcapPath = await resolveUploadPath(pcapFileName, user_id, session_id, PCAP_EXTENSIONS);
        const safeKeylogPath = await resolveUploadPath(keylogFileName, user_id, session_id, KEYLOG_EXTENSIONS);

        // ── Step 0: 配置 tshark 环境变量 ──
        const tsharkEnv = {
          ...process.env,
          PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`
        };
        const execOpts = { maxBuffer: 10 * 1024 * 1024, env: tsharkEnv };

        // ── Step 1: TLS 握手阶段安全分析（不使用密钥） ──
        console.error(`[analyze_ssl_tls] Step1 TLS握手分析（不使用密钥）`);
        const { stdout: handshakeOut } = await execFileAsync(tsharkPath, [
          '-r', safePcapPath, '-T', 'fields',
          '-e', 'tcp.stream',
          '-e', 'tls.handshake.type',
          '-e', 'tls.handshake.version',
          '-e', 'tls.handshake.extensions_server_name',
          '-e', 'tls.handshake.ciphersuite',
          '-e', 'ip.src', '-e', 'ip.dst',
          '-e', 'frame.time_epoch',
          '-Y', 'tls.handshake'
        ], execOpts);

        // ── 密码套件名称映射表（常用） ──
        const CIPHER_NAMES = {
          0x0000: 'TLS_NULL_WITH_NULL_NULL',
          0x0001: 'TLS_RSA_WITH_NULL_MD5',
          0x0002: 'TLS_RSA_WITH_NULL_SHA',
          0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
          0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
          0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
          0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
          0x0016: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
          0x0017: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
          0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
          0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
          0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
          0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
          0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
          0x0062: 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
          0x0063: 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
          0x006B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
          0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
          0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
          0xC007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
          0xC011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
          0xC012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
          0xC023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
          0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
          0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
          0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
          0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
          0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
          0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
          0x1301: 'TLS_AES_128_GCM_SHA256',
          0x1302: 'TLS_AES_256_GCM_SHA384',
          0x1303: 'TLS_CHACHA20_POLY1305_SHA256'
        };

        const WEAK_PATTERNS = /NULL|RC4|DES(?!_POLY)|_anon_|EXPORT|EXP1024|WITH_NULL|3DES/;

        function getCipherName(hex) {
          if (hex === '' || hex === undefined || hex === null) return 'unknown';
          const num = parseInt(hex, 16);
          if (CIPHER_NAMES[num]) return CIPHER_NAMES[num];
          return `0x${num.toString(16).toUpperCase().padStart(4, '0')}`;
        }

        function isWeakCipher(hex) {
          if (hex === '' || hex === undefined || hex === null) return false;
          const name = getCipherName(hex);
          return WEAK_PATTERNS.test(name);
        }

        // 解析握手数据，按 TCP 流分组
        const handshakeData = {};
        for (const line of handshakeOut.split(/\r?\n/)) {
          if (!line.trim()) continue;
          const [streamStr, typeStr, version, sni, ciphersuite, srcIp, dstIp, timeStr] = line.split('\t');
          const streamIdx = parseInt(streamStr);
          if (isNaN(streamIdx)) continue;
          if (!handshakeData[streamIdx]) {
            handshakeData[streamIdx] = {
              streamIndex: streamIdx,
              serverNames: new Set(),
              clientVersions: new Set(),
              cipherSuites: new Set(),
              handshakeTypes: new Set(),
              srcIps: new Set(),
              dstIps: new Set(),
              firstTime: null,
              lastTime: null
            };
          }
          const hd = handshakeData[streamIdx];
          const t = parseFloat(timeStr);
          if (t && (hd.firstTime === null || t < hd.firstTime)) hd.firstTime = t;
          if (t && (hd.lastTime === null || t > hd.lastTime)) hd.lastTime = t;
          if (typeStr) hd.handshakeTypes.add(parseInt(typeStr));
          if (version) hd.clientVersions.add(version);
          if (sni) hd.serverNames.add(sni);
          if (ciphersuite) hd.cipherSuites.add(ciphersuite);
          if (srcIp) hd.srcIps.add(srcIp);
          if (dstIp) hd.dstIps.add(dstIp);
        }

        const tlsStreamIndices = Object.keys(handshakeData).map(Number).sort((a, b) => a - b);

        if (tlsStreamIndices.length === 0) {
          // 无 TLS 握手数据，检查是否有其它加密流量
          const { stdout: tlsCheck } = await execFileAsync(tsharkPath, [
            '-r', safePcapPath, '-T', 'fields', '-e', 'tcp.port',
            '-Y', 'tcp.port == 443', '-c', '5'
          ], execOpts);
          if (!tlsCheck.trim()) {
            const noTlsResult = {
              pcapFileName,
              keylogFileName,
              user_id,
              session_id,
              tlsHandshake: null,
              decryptedTraffic: null,
              httpIssues: [],
              summary: '未在PCAP中发现TLS握手流量，无法进行SSL/TLS分析。'
            };
            return { content: [{ type: 'text', text: JSON.stringify(noTlsResult, null, 2) }] };
          }
        }

        // TLS握手安全检测
        const handshakes = [];
        for (const idx of tlsStreamIndices) {
          const hd = handshakeData[idx];
          const hIssues = [];

          // 检测弱版本
          for (const ver of hd.clientVersions) {
            const verNum = parseInt(ver, 16);
            if (verNum <= 0x0301) {
              hIssues.push({
                type: 'TLS_WEAK_VERSION',
                severity: 'critical',
                description: `检测到TLS版本 ${ver} (TLS 1.0 或更低)，存在已知安全漏洞（BEAST、POODLE）`,
                detail: { version: ver }
              });
            } else if (verNum === 0x0302) {
              hIssues.push({
                type: 'TLS_WEAK_VERSION',
                severity: 'high',
                description: `检测到TLS版本 ${ver} (TLS 1.1)，属于已弃用的不安全版本`,
                detail: { version: ver }
              });
            } else if (verNum === 0x0303) {
              hIssues.push({
                type: 'TLS_WEAK_VERSION',
                severity: 'low',
                description: `检测到TLS版本 ${ver} (TLS 1.2)，建议升级到TLS 1.3以提升安全性`,
                detail: { version: ver }
              });
            }
          }

          // 检测弱密码套件
          const weakCiphers = [...hd.cipherSuites].filter(c => isWeakCipher(c));
          if (weakCiphers.length > 0) {
            hIssues.push({
              type: 'TLS_WEAK_CIPHER',
              severity: 'high',
              description: `检测到 ${weakCiphers.length} 个弱密码套件: ${weakCiphers.map(c => getCipherName(c)).join(', ')}`,
              detail: {
                count: weakCiphers.length,
                ciphers: weakCiphers.map(c => ({ code: `0x${parseInt(c, 16).toString(16).toUpperCase()}`, name: getCipherName(c) }))
              }
            });
          }

          // 检测缺少SNI
          if (hd.serverNames.size === 0) {
            hIssues.push({
              type: 'TLS_NO_SNI',
              severity: 'low',
              description: 'Client Hello缺少SNI (Server Name Indication) 扩展',
              detail: {}
            });
          }

          // 检测握手失败：有Client Hello但没有Server Hello
          const hasClientHello = hd.handshakeTypes.has(1);
          const hasServerHello = hd.handshakeTypes.has(2);
          if (hasClientHello && !hasServerHello) {
            hIssues.push({
              type: 'TLS_HANDSHAKE_FAILURE',
              severity: 'high',
              description: '检测到Client Hello但无Server Hello响应，TLS握手可能失败',
              detail: { handshakeTypes: [...hd.handshakeTypes] }
            });
          }

          handshakes.push({
            streamIndex: idx,
            serverNames: [...hd.serverNames],
            clientVersions: [...hd.clientVersions],
            cipherSuites: [...hd.cipherSuites].map(c => getCipherName(c)),
            srcIps: [...hd.srcIps],
            dstIps: [...hd.dstIps],
            handshakeTypes: [...hd.handshakeTypes],
            issues: hIssues
          });
        }

        const totalHandshakeIssues = handshakes.reduce((s, h) => s + h.issues.length, 0);
        const tlsSummary = tlsStreamIndices.length === 0
          ? '未发现TLS握手流量。'
          : `发现 ${tlsStreamIndices.length} 个TLS流，${handshakes.filter(h => h.issues.length > 0).length} 个流存在安全问题，共 ${totalHandshakeIssues} 个问题。`;

        console.error(`[analyze_ssl_tls] Step1 完成: ${tlsStreamIndices.length} 个TLS流，${totalHandshakeIssues} 个问题`);

        // ── Step 2: 使用 SSLKEYLOGFILE 解密流量 ──
        console.error(`[analyze_ssl_tls] Step2 使用SSLKEYLOGFILE解密`);
        const { stdout: decryptedOut } = await execFileAsync(tsharkPath, [
          '-o', `tls.keylog_file:${safeKeylogPath}`,
          '-r', safePcapPath, '-T', 'fields',
          '-e', 'tcp.stream',
          '-e', 'ip.src', '-e', 'ip.dst',
          '-e', 'frame.time_epoch',
          '-e', 'http.request.method', '-e', 'http.request.uri',
          '-e', 'http.host', '-e', 'http.user_agent',
          '-e', 'http.response.code', '-e', 'http.content_length',
          '-e', 'http.content_type', '-e', 'http.location',
          '-e', 'http.file_data',
          '-Y', 'http'
        ], { maxBuffer: 50 * 1024 * 1024, env: tsharkEnv });

        // ── Step 3: 解析解密数据 + 总体行为分析 ──
        const streamHttpData = {};
        let totalRequests = 0, totalResponses = 0;
        const hostCounts = {}, methodCounts = {}, userAgentSet = new Set();
        const contentTypeCounts = {};
        const uriRequests = {};  // key: "METHOD uri", value: { count, responses: [{code, bodySummary}] }

        for (const line of decryptedOut.split(/\r?\n/)) {
          if (!line.trim()) continue;
          const parts = line.split('\t');
          const streamIdx = parseInt(parts[0]);
          if (isNaN(streamIdx)) continue;
          const srcIp = parts[1], dstIp = parts[2], timeStr = parts[3];
          const method = parts[4], uri = parts[5], host = parts[6], userAgent = parts[7];
          const respCodeStr = parts[8], contentLength = parts[9];
          const contentType = parts[10], location = parts[11];
          const fileDataHex = parts[12];

          if (!streamHttpData[streamIdx]) {
            streamHttpData[streamIdx] = { streamIndex: streamIdx, packets: [], srcIps: new Set() };
          }
          const sd = streamHttpData[streamIdx];
          sd.srcIps.add(srcIp);

          const entry = { time: parseFloat(timeStr), srcIp, dstIp };

          if (method) {
            entry.type = 'request';
            entry.method = method;
            entry.uri = uri || '';
            if (host) entry.host = host;
            if (userAgent) entry.userAgent = userAgent;
            totalRequests++;
            if (host) hostCounts[host] = (hostCounts[host] || 0) + 1;
            methodCounts[method] = (methodCounts[method] || 0) + 1;
            if (userAgent) userAgentSet.add(userAgent);

            // URI聚合：用method+uri做key
            const uriKey = `${method} ${uri}`;
            if (!uriRequests[uriKey]) uriRequests[uriKey] = { method, uri, count: 0, responses: [] };
            uriRequests[uriKey].count++;
          } else if (respCodeStr) {
            entry.type = 'response';
            entry.code = parseInt(respCodeStr);
            if (contentLength) entry.contentLength = parseInt(contentLength);
            if (contentType) entry.contentType = contentType;
            entry.location = location || null;
            totalResponses++;
            if (contentType) contentTypeCounts[contentType] = (contentTypeCounts[contentType] || 0) + 1;

            // 收集响应摘要：关联最近的请求URI
            if (fileDataHex && fileDataHex.length >= 8) {
              try {
                const decoded = decodeHexFields(fileDataHex);
                // decodeHexFields 可能返回带 [binary data] 标记的原始 hex
                if (decoded && !decoded.includes('[binary data]')) {
                  entry.bodySummary = decoded.substring(0, 200);
                }
              } catch { /* ignore decode errors */ }
            }

            // 将响应关联到最近的请求
            const recentUris = Object.keys(uriRequests);
            if (recentUris.length > 0) {
              const lastKey = recentUris[recentUris.length - 1];
              uriRequests[lastKey].responses.push({
                code: entry.code,
                contentType: contentType || '',
                bodySummary: entry.bodySummary || ''
              });
            }
          }
          sd.packets.push(entry);
        }

        // 排序每个流的包
        for (const idx of Object.keys(streamHttpData)) {
          streamHttpData[idx].packets.sort((a, b) => a.time - b.time);
        }
        const httpStreamIndices = Object.keys(streamHttpData).map(Number).sort((a, b) => a - b);

        // 解密校验
        const decryptionVerified = totalRequests > 0;
        let decryptionWarning = null;
        if (!decryptionVerified && tlsStreamIndices.length > 0) {
          decryptionWarning = 'DECRYPTION_MAYBE_FAILED: 存在TLS握手流量但解密后HTTP请求数为0，请检查SSLKEYLOGFILE是否与PCAP匹配';
        }

        // 构建 topUris（按频次降序，取前30）
        const topUris = Object.values(uriRequests)
          .sort((a, b) => b.count - a.count)
          .slice(0, 30)
          .map(u => ({
            method: u.method,
            uri: u.uri,
            count: u.count,
            responseCode: u.responses.length > 0 ? u.responses[0].code : null,
            responseSummary: u.responses.length > 0 ? (u.responses[0].bodySummary || '').substring(0, 200) : ''
          }));

        console.error(`[analyze_ssl_tls] Step3 完成: ${totalRequests} 个HTTP请求, ${totalResponses} 个响应, ${httpStreamIndices.length} 个流`);

        // ── Step 4: HTTP 问题检测 ──
        const httpIssues = [];
        for (const idx of httpStreamIndices) {
          const sd = streamHttpData[idx];
          const streamIssues = [];

          // 1. HTTP 4xx 错误
          const codes4xx = sd.packets.filter(p => p.type === 'response' && p.code >= 400 && p.code < 500);
          if (codes4xx.length > 0) {
            streamIssues.push({
              type: 'HTTP_4XX_ERROR',
              severity: 'medium',
              description: `检测到 ${codes4xx.length} 个HTTP 4xx客户端错误响应`,
              detail: { count: codes4xx.length, codes: [...new Set(codes4xx.map(p => p.code))] }
            });
          }

          // 2. HTTP 5xx 错误
          const codes5xx = sd.packets.filter(p => p.type === 'response' && p.code >= 500 && p.code < 600);
          if (codes5xx.length > 0) {
            streamIssues.push({
              type: 'HTTP_5XX_ERROR',
              severity: 'high',
              description: `检测到 ${codes5xx.length} 个HTTP 5xx服务器错误响应`,
              detail: { count: codes5xx.length, codes: [...new Set(codes5xx.map(p => p.code))] }
            });
          }

          // 3. HTTP 重定向循环：同一流内连续出现 >=3 次 3xx 响应
          const respSequence = sd.packets.filter(p => p.type === 'response').map(p => p.code);
          let maxConsecutive = 0, cur = 0;
          for (const code of respSequence) {
            if (code >= 300 && code < 400) { cur++; if (cur > maxConsecutive) maxConsecutive = cur; }
            else cur = 0;
          }
          if (maxConsecutive >= 3) {
            streamIssues.push({
              type: 'HTTP_REDIRECT_LOOP',
              severity: 'high',
              description: `同一流内连续出现 ${maxConsecutive} 次3xx重定向响应，疑似重定向循环`,
              detail: { consecutiveRedirects: maxConsecutive }
            });
          }

          // 4. HTTP 响应极慢：请求到响应时间差 > 30s
          const slowPairs = [];
          let maxSlow = 0;
          for (let i = 0; i < sd.packets.length; i++) {
            if (sd.packets[i].type !== 'request') continue;
            const reqTime = sd.packets[i].time;
            for (let j = i + 1; j < sd.packets.length; j++) {
              if (sd.packets[j].type === 'response') {
                const elapsed = sd.packets[j].time - reqTime;
                if (elapsed > 30) {
                  slowPairs.push({ uri: sd.packets[i].uri, elapsed: elapsed.toFixed(2) });
                  if (elapsed > maxSlow) maxSlow = elapsed;
                }
                break;
              }
            }
          }
          if (slowPairs.length > 0) {
            streamIssues.push({
              type: 'HTTP_SLOW_RESPONSE',
              severity: 'medium',
              description: `检测到 ${slowPairs.length} 个HTTP响应耗时超过30秒(最长${maxSlow.toFixed(2)}秒)`,
              detail: { count: slowPairs.length, maxElapsed: maxSlow.toFixed(2), samples: slowPairs.slice(0, 5) }
            });
          }

          if (streamIssues.length > 0) {
            httpIssues.push({
              streamIndex: idx,
              protocol: 'HTTP',
              packetCount: sd.packets.length,
              detectedIssues: streamIssues
            });
          }
        }

        console.error(`[analyze_ssl_tls] Step4 完成: ${httpIssues.length} 个流存在HTTP问题`);

        // ── Step 5: 构建 JSON 输出 ──
        const hostsSorted = Object.entries(hostCounts)
          .sort((a, b) => b[1] - a[1])
          .map(([host, count]) => ({ host, count }));

        const result = {
          pcapFileName,
          keylogFileName,
          user_id,
          session_id,
          tlsHandshake: {
            totalTlsStreams: tlsStreamIndices.length,
            handshakes,
            summary: tlsSummary
          },
          decryptedTraffic: {
            decryptionVerified,
            decryptionWarning,
            totalStreams: httpStreamIndices.length,
            totalHttpRequests: totalRequests,
            totalHttpResponses: totalResponses,
            hosts: hostsSorted,
            methods: methodCounts,
            userAgents: [...userAgentSet],
            contentTypes: contentTypeCounts,
            topUris
          },
          httpIssues,
          summary: httpIssues.length === 0
            ? (decryptionVerified
              ? `解密了 ${httpStreamIndices.length} 个TCP流中的 ${totalRequests} 个HTTP请求/${totalResponses} 个响应，未发现HTTP问题。`
              : `TLS握手分析完成（${tlsStreamIndices.length} 个流），但HTTP解密未发现明文流量。`)
            : `解密了 ${httpStreamIndices.length} 个TCP流中的 ${totalRequests} 个HTTP请求/${totalResponses} 个响应，发现 ${httpIssues.length} 个流存在问题，共 ${httpIssues.reduce((s, i) => s + i.detectedIssues.length, 0)} 个HTTP问题。`
        };

        // 输出截断保护（复用L7模式: 200KB上限，按比例裁剪issues数组）
        let jsonOutput = JSON.stringify(result, null, 2);
        const maxChars = 200000;
        if (jsonOutput.length > maxChars) {
          const trimFactor = maxChars / jsonOutput.length;
          const truncatedResult = { ...result };
          // 裁剪 httpIssues（HTTP问题检测结果）
          truncatedResult.httpIssues = result.httpIssues.slice(0, Math.floor(result.httpIssues.length * trimFactor));
          // 裁剪 handshakes（如果仍有必要）
          if (JSON.stringify(truncatedResult).length > maxChars) {
            truncatedResult.tlsHandshake = {
              ...result.tlsHandshake,
              handshakes: result.tlsHandshake.handshakes.slice(0, Math.floor(result.tlsHandshake.handshakes.length * trimFactor))
            };
          }
          // 裁剪 topUris
          if (JSON.stringify(truncatedResult).length > maxChars) {
            truncatedResult.decryptedTraffic = {
              ...result.decryptedTraffic,
              topUris: result.decryptedTraffic.topUris.slice(0, Math.floor(result.decryptedTraffic.topUris.length * trimFactor))
            };
          }
          truncatedResult.summary += ' (输出已截断，部分详情被省略)';
          jsonOutput = JSON.stringify(truncatedResult, null, 2);
        }

        console.error(`[analyze_ssl_tls] 分析完成: TLS流=${tlsStreamIndices.length}, HTTP流=${httpStreamIndices.length}, 问题流=${httpIssues.length}`);
        return { content: [{ type: 'text', text: jsonOutput }] };
      } catch (error) {
        console.error(`[analyze_ssl_tls] 执行错误: ${error.message}`);
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
  'summary_stats_prompt',
  {
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
  },
  ({ pcapFileName, user_id, session_id }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请分析 PCAP 文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}）的协议层级统计，重点关注：
1. 各协议占比与流量分布（tcp/udp/http/dns/tls 等的包数与字节数）
2. 异常协议组合或非预期协议（如明文 telnet、可疑 C2 协议）
3. 占比突出的协议是否反映业务特征或异常行为
4. 结合协议层级分布给出整体网络健康度评估与排查建议`
      }
    }]
  })
);

server.prompt(
  'conversations_prompt',
  {
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
  },
  ({ pcapFileName, user_id, session_id }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请分析 PCAP 文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}）的 TCP 会话统计，重点关注：
1. 最活跃的 IP 通信对（按包数/字节数排序）
2. 会话时长与数据量分布，识别长连接或大流量会话
3. 异常通信模式（非标准端口、扫描行为、单向流量等）
4. 潜在网络问题线索（如大量短连接、重连、异常外联）`
      }
    }]
  })
);

server.prompt(
  'check_ip_threats_prompt',
  {
    ip: z.string().describe('待查询的 IP 地址，例如：192.168.1.1'),
  },
  ({ ip }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请针对 IP 地址 ${ip} 进行威胁情报分析：
1. 与 URLhaus 黑名单比对，判断是否为已知恶意 IP
2. 评估该 IP 的信誉情况（结合返回结果说明）
3. 如命中黑名单，推测可能关联的恶意行为（恶意软件分发、C2 等）
4. 给出安全处置建议（封禁、加白、进一步取证等）`
      }
    }]
  })
);

server.prompt(
  'exec_tshark_prompt',
  {
    pcapFileName: z.string().describe('PCAP文件名称（仅文件名）'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
    tsharkArgs: z.string().optional().describe('可选的tshark参数提示'),
  },
  ({ pcapFileName, user_id, session_id, tsharkArgs = '' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `【重要提示】当WireMCP的其他内置工具（如analyze_pcap、get_conversations、extract_credentials、check_ip_threats等）无法满足你的分析需求时，再使用exec_tshark工具执行自定义tshark命令。
请分析PCAP文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}），需要获取特定数据时：
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
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
  },
  ({ pcapFileName, user_id, session_id }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请对 PCAP 文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}）进行总览分析：
1. 整体流量模式（时间分布、流量峰值、主要通信方向）
2. 唯一 IP 及其交互关系（客户端/服务端角色、内外网划分）
3. 使用的协议与服务（端口、应用层协议识别）
4. 值得关注的事件或异常（扫描、爆破、非标准端口、明文敏感数据）
5. 潜在安全风险与下一步深入分析建议`
      }
    }]
  })
);

server.prompt(
  'extract_credentials_prompt',
  {
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
  },
  ({ pcapFileName, user_id, session_id }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请分析 PCAP 文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}）中可能存在的凭据泄露：
1. 检查明文凭据（HTTP Basic Auth、FTP USER/PASS、Telnet 登录）
2. 识别 Kerberos 认证尝试（AS-REQ/AS-REP/TGS-REQ，提取用户名与域）
3. 提取哈希凭据（如 $krb5pa$、$krb5asrep$ 格式，并给出 hashcat 破解模式）
4. 给出凭据处置与加固建议（禁用弱协议、改密、启用加密、审计等）`
      }
    }]
  })
);

server.prompt(
  'analyze_l4_network_prompt',
  {
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
    tsharkArgs: z.string().optional().describe('可选的 tshark 过滤参数，例如：-Y "ip.addr == 10.0.0.1"'),
  },
  ({ pcapFileName, user_id, session_id, tsharkArgs = '' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请对 PCAP 文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}）进行传输层（四层）网络问题分析，重点解读 analyze_l4_network 返回的 JSON 报告：
1. 逐流检查 TCP 连接建立：SYN 无响应、端口未开放（RST 拒绝）、SYN/SYN-ACK 重传
2. 传输可靠性问题：超时重传、重复 ACK、零窗口（区分已恢复/未恢复）
3. 异常断开：异常 RST（未正常挥手）、四次挥手不完整
4. 攻击检测：SYN Flood（大量 SYN 无响应流 + 源 IP 分布）
5. 注意单向流量场景：仅单向捕获时部分检测会跳过，需说明影响
6. 结合 severity（critical/high/medium/low）给出处置优先级建议

${tsharkArgs ? `建议使用的过滤参数: ${tsharkArgs}` : '未指定过滤参数时，将对命中的全部 TCP 流进行分析。'}`
      }
    }]
  })
);

server.prompt(
  'analyze_l7_network_prompt',
  {
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
    tsharkArgs: z.string().optional().describe('可选的 tshark 过滤参数，例如：-Y "http"'),
  },
  ({ pcapFileName, user_id, session_id, tsharkArgs = '' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请对 PCAP 文件 ${pcapFileName}（user_id=${user_id}, session_id=${session_id}）进行应用层（七层）网络问题分析，重点解读 analyze_l7_network 返回的 JSON 报告：
1. HTTP 错误：4xx 客户端错误、5xx 服务端错误，统计状态码分布
2. 重定向循环：同一流内连续 ≥3 次 3xx 响应
3. 响应极慢：请求到响应时间差 > 30s 的慢响应
4. 响应体完整性：声明 Content-Length 但存在重传 + 服务端 FIN，可能截断
5. 服务端提前 FIN / 请求无响应：服务端未响应完毕就关闭连接，或无 FIN 无响应
6. DNS 问题：NXDOMAIN、SERVFAIL、REFUSED、查询超时（有查询无响应）
7. TLS 解密相关提示：基于 TLS 的请求若服务端有加密应用数据但未解密，会提示而非误报

${tsharkArgs ? `建议使用的过滤参数: ${tsharkArgs}` : '未指定过滤参数时，将对命中的全部 TCP 流与 DNS 事务进行分析。'}`
      }
    }]
  })
);

server.prompt(
  'analyze_ssl_tls_prompt',
  {
    pcapFileName: z.string().describe('待分析的 PCAP 文件名称（仅文件名），例如：demo.pcap'),
    keylogFileName: z.string().describe('SSLKEYLOGFILE 文件名称（仅文件名），例如：sslkeylog.txt'),
    user_id: z.string().describe('用户ID'),
    session_id: z.string().describe('会话ID'),
  },
  ({ pcapFileName, keylogFileName, user_id, session_id }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `请对 PCAP 文件 ${pcapFileName}（密钥文件 ${keylogFileName}, user_id=${user_id}, session_id=${session_id}）进行 SSL/TLS 解密分析，重点解读 analyze_ssl_tls 返回的 JSON 报告：

【TLS 握手安全】
1. 弱版本：TLS 1.0/1.1 已弃用、TLS 1.2 建议升级 1.3
2. 弱密码套件：RC4、DES、3DES、NULL、EXPORT、匿名套件等
3. SNI 缺失：Client Hello 未携带 SNI
4. 握手失败：有 Client Hello 无 Server Hello

【解密后 HTTP 明文】
5. 请求行为：方法/URI/Host/User-Agent 统计，Top URI 频次
6. 响应摘要：状态码、Content-Type、响应体摘要
7. HTTP 问题：4xx/5xx、重定向循环、响应过慢
8. 解密校验：若存在 TLS 流但解密后请求数为 0，提示密钥可能不匹配

请分别给出 TLS 加固建议与 HTTP 层处置建议。`
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
  const port = portIndex !== -1 ? parseInt(args[portIndex + 1]) : 10001;
  const sseArg = args.find(a => a.startsWith('--sse='));
  const isSse = sseArg ? sseArg.split('=')[1] === 'true' : false;

  if (isHttp) {
    // HTTP mode: Streamable HTTP Transport (stateless mode)
    // Each request gets a fresh McpServer + Transport, no Session-ID required
    // SSE disabled by default (JSON response), use --sse=true to enable SSE streaming
    const getServer = () => {
      const server = new McpServer({
        name: 'wiremcp',
        version: '1.0.0',
      });
      registerTools(server);
      registerPrompts(server);
      return server;
    };

    /**
     * 创建令牌桶 QPS 限流中间件（全局共享一个桶）
     * 容量 = maxQps，按经过时间匀速补充令牌；请求到达消耗 1 个，不足则拒绝
     * Node 单线程，限流检查为同步操作，天然原子安全
     * @param {number} maxQps - 每秒最大请求数（=令牌桶容量）
     * @param {string} routeName - 路由名，用于日志标识
     */
    function createTokenBucketQpsLimiter(maxQps, routeName) {
      let tokens = maxQps;
      let lastRefill = Date.now();
      return (req, res, next) => {
        const now = Date.now();
        const elapsed = (now - lastRefill) / 1000;
        tokens = Math.min(maxQps, tokens + elapsed * maxQps);
        lastRefill = now;
        if (tokens >= 1) {
          tokens -= 1;
          return next();
        }
        console.error(
          `[rate-limit] ${new Date().toISOString()} ${routeName} QPS limit (${maxQps}/s) exceeded, rejected tokens=${tokens.toFixed(2)} client=${req.ip}`
        );
        res.status(429).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: `Rate limit exceeded: max ${maxQps} QPS` },
          id: null,
        });
      };
    }

    /**
     * 创建并发数限流中间件
     * 内存计数器，进入时 +1，响应关闭时 -1；超过 maxConcurrent 则拒绝
     * 递减挂在 res 'close' 事件，覆盖成功/校验失败/中间件报错/客户端断连全部路径
     * @param {number} maxConcurrent - 最大并发数
     * @param {string} routeName - 路由名，用于日志标识
     */
    function createConcurrencyLimiter(maxConcurrent, routeName) {
      let inflight = 0;
      return (req, res, next) => {
        if (inflight >= maxConcurrent) {
          console.error(
            `[concurrency] ${new Date().toISOString()} ${routeName} concurrency limit (${maxConcurrent}) reached, rejected inflight=${inflight} client=${req.ip}`
          );
          return res.status(429).json({
            success: false,
            error: `Concurrency limit (${maxConcurrent}) reached, please retry later`,
          });
        }
        inflight++;
        res.on('close', () => {
          inflight--;
        });
        next();
      };
    }

    const mcpQpsLimiter = createTokenBucketQpsLimiter(50, '/mcp/wiremcp');
    const uploadConcurrencyLimiter = createConcurrencyLimiter(20, '/mcp/upload');

    const app = express();
    app.use(express.json());
    app.all('/mcp/wiremcp', mcpQpsLimiter, async (req, res) => {
      const server = getServer();
      try {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined, // Stateless: no session management
          enableJsonResponse: !isSse,
        });
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
        // Cleanup when request closes
        res.on('close', () => {
          transport.close();
          server.close();
        });
      } catch (err) {
        console.error(`Error handling MCP request: ${err.message}`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal error' },
            id: null,
          });
        }
      }
    });
    // Reject GET/DELETE (stateless mode)
    app.get('/mcp/wiremcp', (req, res) => {
      res.status(405).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Method not allowed' },
        id: null,
      });
    });
    app.delete('/mcp/wiremcp', (req, res) => {
      res.status(405).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Method not allowed' },
        id: null,
      });
    });

    // 文件上传接口：接收单个文件，存放到 uploads/<user_id>/<session_id>/ 目录（不存在则创建）
    // 一次请求只上传一个文件（字段名 file），多个文件需多次请求
    app.post('/mcp/upload', uploadConcurrencyLimiter, uploadSingleFile, async (req, res) => {
      let tempFilePath = null;
      try {
        const userId = validateUserId(req.body.user_id);
        const sessionId = validateSessionId(req.body.session_id);
        if (!req.file) {
          return res.status(400).json({
            success: false,
            error: 'Missing upload file (multipart field name should be file).',
          });
        }
        tempFilePath = req.file.path;
        const { filename, ext } = sanitizeUploadFilename(req.file.originalname);

        const targetDir = path.join(UPLOAD_BASE_DIR, userId, sessionId);
        await fs.mkdir(targetDir, { recursive: true });

        const targetPath = path.join(targetDir, filename);
        await fs.rename(tempFilePath, targetPath);
        tempFilePath = null;

        console.error(
          `[upload] file saved: user=${userId}, session=${sessionId}, file=${filename}, size=${req.file.size}bytes`
        );

        res.json({
          success: true,
          user_id: userId,
          session_id: sessionId,
          filename,
          extension: ext,
          size: req.file.size,
          savedPath: targetPath,
        });
      } catch (error) {
        console.error(`[upload] upload failed: ${error.message}`);
        const msg = error.message || 'upload failed';
        if (msg.includes('user_id') || msg.includes('session_id') ||
            msg.includes('extension') || msg.includes('Missing')) {
          return res.status(400).json({ success: false, error: msg });
        }
        return res.status(500).json({ success: false, error: msg });
      } finally {
        if (tempFilePath) {
          await fs.unlink(tempFilePath).catch(e =>
            console.error(`[upload] failed to clean temp file: ${e.message}`)
          );
        }
      }
    });

    app.listen(port, () => {
      console.error(`WireMCP HTTP server listening on http://localhost:${port}/mcp/wiremcp (stateless mode, SSE=${isSse})`);
      console.error(`WireMCP upload endpoint: POST http://localhost:${port}/mcp/upload`);
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