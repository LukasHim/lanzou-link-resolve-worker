import * as cheerio from 'cheerio';

interface LinkResolverOptions {
	url: URL;
	password?: string;
	solveURL?: boolean;
	getLength?: boolean;
}

interface ResolveResult {
	downURL: URL;
	filename: string;
	filesize: number;
	warns?: string[];
}

interface ResolverState {
	cookie: string;
	debug: boolean;
	lastEncryptArg?: string;
}

const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';

const accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
const acceptLanguage = 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7';

function isEmpty(val: unknown) {
	return (
		val === '' ||
		val === null ||
		val === undefined ||
		(typeof val === 'object' && Object.keys(val as object).length === 0) ||
		(Array.isArray(val) && val.length === 0)
	);
}

function matchGroup(str: string, regex: RegExp, group = 1): string {
	const match = str.match(regex);
	if (!match || typeof match[group] === 'undefined') {
		throw new Error(`正则匹配失败：${regex}`);
	}
	return match[group];
}

function createAjaxmPHPBody(body: Record<string, string>) {
	return new URLSearchParams(body).toString();
}

export function getAcwScV2(arg1: string): string {
	const maskBase64 = 'MzAwMDE3NjAwMDg1NjAwNjA2MTUwMTUzMzAwMzY5MDAyNzgwMDM3NQ==';
	const mask = atob(maskBase64);

	const posList = [
		15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23, 25, 13, 6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4, 17, 5, 3, 28,
		34, 37, 12, 36,
	];

	const map: Record<number, number> = {};
	posList.forEach((pos, idx) => (map[pos] = idx));

	const output: string[] = new Array(posList.length).fill('');

	for (let i = 1; i <= arg1.length; i++) {
		const targetIndex = map[i];
		if (targetIndex !== undefined) {
			output[targetIndex] = arg1[i - 1];
		}
	}

	const rearranged = output.join('');

	let result = '';
	let i = 0;

	while (i < rearranged.length && i < mask.length) {
		const dataChunk = parseInt(rearranged.substr(i, 2), 16);
		const maskChunk = parseInt(mask.substr(i, 2), 16);

		const xorResult = dataChunk ^ maskChunk;

		let hex = xorResult.toString(16);
		if (hex.length < 2) hex = '0' + hex;

		result += hex;
		i += 2;
	}

	return result.toLowerCase();
}

async function debugFetch(state: ResolverState, url: string, init: RequestInit): Promise<Response> {
	if (state.debug) {
		console.log('[fetch]', url);
		console.log('[init]', init);
	}

	const resp = await fetch(url, init);

	if (state.debug) {
		console.log('[response]', resp.status, url);
	}

	return resp;
}

export class LinkResolver {
	private readonly options: Readonly<LinkResolverOptions>;
	private document: cheerio.CheerioAPI | null = null;

	private state: ResolverState = {
		cookie: '',
		lastEncryptArg: '',
		debug: false,
	};

	constructor(options: LinkResolverOptions & { debug?: boolean }) {
		this.options = Object.freeze({
			solveURL: true,
			getLength: false,
			...options,
			url: typeof options.url === 'string' ? new URL(options.url) : options.url,
		});

		this.state.debug = !!(options as any).debug;
	}

	private buildHeaders(extra?: HeadersInit): HeadersInit {
		return {
			accept,
			'user-agent': userAgent,
			'accept-language': acceptLanguage,
			'accept-encoding': 'gzip, deflate',
			connection: 'keep-alive',
			cookie: this.state.cookie,
			...extra,
		};
	}

	public async resolve(): Promise<ResolveResult> {
		const pageURL = new URL(this.options.url.pathname, this.options.url.origin);

		if (this.state.debug) {
			console.log('[resolve:start]', pageURL.toString());
		}

		const html = await (
			await debugFetch(this.state, pageURL.toString(), {
				method: 'GET',
				headers: this.buildHeaders(),
			})
		).text();

		this.document = cheerio.load(html);

		const match = html.match(/var arg1='(.+?)';/);

		if (!this.state.cookie && match) {
			const encryptArg = match[1];

			this.state.lastEncryptArg = encryptArg;

			this.state.cookie = `acw_sc__v2=${getAcwScV2(encryptArg)}`;

			if (this.state.debug) {
				console.log('[cookie]', this.state.cookie);
			}

			return this.resolve();
		}

		if (this.document('.off').length) {
			throw new Error(this.document('.off').text());
		}

		if (this.document('#pwd').length) {
			return this.resolveWithPassword(pageURL);
		}

		return this.resolveWithoutPassword(pageURL);
	}

	private async resolveWithPassword(pageURL: URL): Promise<ResolveResult> {
		const script = this.extractScript(this.document!);

		const body = createAjaxmPHPBody({
			action: 'downprocess',
			sign: matchGroup(script, /'sign':'(.*?)'/),
			p: this.options.password!,
			kd: matchGroup(script, /var\s+kdns\s*=\s*(\d+);/) || '0',
		});

		const apiURL = `${this.options.url.origin}/ajaxm.php` + matchGroup(script, /'*ajaxm.php(.*?)'/);

		const resp = (await (
			await debugFetch(this.state, apiURL, {
				method: 'POST',
				headers: this.buildHeaders({
					'content-type': 'application/x-www-form-urlencoded',
					referer: pageURL.toString(),
					origin: pageURL.origin,
					'x-requested-with': 'XMLHttpRequest',
				}),
				body,
			})
		).json()) as any;

		if (!resp.zt) {
			throw new Error(`${resp.inf}`);
		}

		const downURL = new URL('/file/' + resp.url, resp.dom);

		let info: any = { redirectedURL: downURL };

		if (this.options.solveURL) {
			info = await this.getMoreInfoFromRedirectURL(downURL, this.options.getLength);
		}

		return {
			downURL: info.redirectedURL,
			filename: info.filename || resp.inf,
			filesize: info.length || 0,
		};
	}

	private async resolveWithoutPassword(pageURL: URL): Promise<ResolveResult> {
		const iframeSrc = this.document!('.ifr2').prop('src');
		if (!iframeSrc) throw new Error('iframe 不存在');

		const iframeURL = new URL(iframeSrc, pageURL.origin);

		const iframeHTML = await (
			await debugFetch(this.state, iframeURL.toString(), {
				method: 'GET',
				headers: this.buildHeaders(),
			})
		).text();

		const iframeDoc = cheerio.load(iframeHTML);
		const script = this.extractScript(iframeDoc);

		const body = createAjaxmPHPBody({
			action: 'downprocess',
			sign: matchGroup(script, /wp_sign = '(.*?)'/),
			signs: matchGroup(script, /ajaxdata = '(.*?)'/),
			websign: matchGroup(script, /ciucjdsdc = '(.*?)'/),
			websignkey: matchGroup(script, /ajaxdata = '(.*?)'/),
			ves: matchGroup(script, /'ves':\s*([\d]+)/),
			kd: matchGroup(script, /var\s+kdns\s*=\s*(\d+);/) || '0',
		});

		const apiURL = `${this.options.url.origin}/ajaxm.php` + matchGroup(script, /'*ajaxm.php(.*?)'/);

		const resp = (await (
			await debugFetch(this.state, apiURL, {
				method: 'POST',
				headers: this.buildHeaders({
					'content-type': 'application/x-www-form-urlencoded',
					referer: iframeURL.toString(),
					origin: iframeURL.origin,
					'x-requested-with': 'XMLHttpRequest',
				}),
				body,
			})
		).json()) as any;

		if (!resp.zt) {
			throw new Error('ajaxm 错误（无密码）');
		}

		const downURL = new URL('/file/' + resp.url, resp.dom);

		let info: any = { redirectedURL: downURL };

		if (this.options.solveURL) {
			info = await this.getMoreInfoFromRedirectURL(downURL, this.options.getLength);
		}

		return {
			downURL: info.redirectedURL,
			filename: info.filename,
			filesize: info.length || 0,
			warns: info.warns || [],
		};
	}

	private async getMoreInfoFromRedirectURL(url: string | URL, getLength = false): Promise<any> {
		const resp = await debugFetch(this.state, url.toString(), {
			method: 'GET',
			redirect: 'manual',
			headers: this.buildHeaders(),
		});

		const location = resp.headers.get('location');

		if (!location) {
			const html = await resp.text();
			const match = html.match(/var arg1='(.+?)';/);

			if (!match) throw new Error('encryptArg 未找到');

			const encryptArg = match[1];

			this.state.lastEncryptArg = encryptArg;

			this.state.cookie = `acw_sc__v2=${getAcwScV2(encryptArg)}`;

			if (this.state.debug) {
				console.log('[cookie]', this.state.cookie);
			}

			return this.getMoreInfoFromRedirectURL(url, getLength);
		}

		const redirectedURL = new URL(location);
		redirectedURL.searchParams.delete('pid');

		if (!getLength) {
			return { redirectedURL };
		}

		const head = await debugFetch(this.state, redirectedURL.toString(), {
			method: 'HEAD',
			headers: this.buildHeaders(),
		});

		const length = head.headers.get('content-length');
		const disposition = head.headers.get('content-disposition');

		if (!length || !disposition) {
			throw new Error('缺少文件信息');
		}

		const filename = decodeURIComponent(matchGroup(disposition, /filename\*?=(?:UTF-8'')?["']?(.*)["']?/));

		return {
			redirectedURL,
			length: Number(length),
			filename,
		};
	}

	private extractScript(doc: cheerio.CheerioAPI): string {
		return doc('script')
			.text()
			.replace(/\/\/.*(?=[\n\r])/g, '')
			.replace(/\/\*[\s\S]*?\*\//g, '');
	}
}
