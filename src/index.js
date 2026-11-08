export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/status") {
        return Response.json({
          success: true,
          message: "OPM Reborn backend aktif",
          database: "connected"
        }, { headers: corsHeaders });
      }

      if (url.pathname === "/api/players") {
        const result = await env.DB.prepare(
          "SELECT id, username, diamond, gold, summon_ticket FROM players"
        ).all();

        return Response.json(result.results, {
          headers: corsHeaders
        });
      }

      return Response.json({
        success: true,
        message: "OPM Reborn API"
      }, { headers: corsHeaders });

    } catch (error) {
      return Response.json({
        success: false,
        error: error.message
      }, {
        status: 500,
        headers: corsHeaders
      });
    }
  }
};