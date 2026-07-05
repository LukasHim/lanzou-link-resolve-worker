import { LinkResolver } from './resolver';
import { returnHtml } from './doc';

export default {
	async fetch(request): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === '/' && !url.search) {
			return returnHtml();
		}
		const lanzouLink = url.searchParams.get('url');
		const password = url.searchParams.get('pwd');
		const desolveURL = url.searchParams.get('desolve') === '' || url.searchParams.get('desolve') === 'true' || false;
		const getMore = url.searchParams.get('more') === '' || url.searchParams.get('more') === 'true' || true;
		const downloadDirect = url.searchParams.get('direct') === '' || url.searchParams.get('direct') === 'true' || false;
		const debug = url.searchParams.get('debug') === '' || url.searchParams.get('debug') === 'true' || false;

		if (!lanzouLink) {
			return new Response(JSON.stringify({ error: "参数 'url' 是必需的！" }), {
				status: 400,
				headers: {
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
				},
			});
		}

		try {
			const resolver = new LinkResolver({
				url: new URL(lanzouLink),
				password: password || undefined,
				solveURL: !desolveURL,
				getLength: getMore,
				// debug: true,
			});

			const result = await resolver.resolve();

			const responseData: { [key: string]: any } = {
				downloadUrl: result.downURL.href,
				filename: result.filename,
				filesize: result.filesize,
			};

			if (debug) {
				responseData.debugInfo = { originalResult: result, requestUrl: lanzouLink };
			}

			if (downloadDirect) {
				return new Response('', {
					status: 302,
					headers: {
						Location: responseData.downloadUrl,
					},
				});
			}

			return new Response(JSON.stringify(responseData), {
				headers: {
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
				},
			});
		} catch (error: any) {
			return new Response(
				JSON.stringify({
					error: '解析链接时发生错误。',
					details: error.message,
				}),
				{
					status: 500,
					headers: {
						'Content-Type': 'application/json',
						'Access-Control-Allow-Origin': '*',
					},
				},
			);
		}
	},
} satisfies ExportedHandler<Env>;
