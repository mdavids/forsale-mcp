#!/bin/bash

echo "# health (geen onderdeel van MCP-stnadaard)"
curl -s https://forsalereg.sidnlabs.nl/health

echo "# Initialize (MCP handshake)"
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | jq .

echo "# Succesful initialize handshake confirmed
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' | jq .

echo "# Tools opvragen"  
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | jq .

echo "# Domein checken (enkel)"
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{
      "name":"check_for_sale",
      "arguments":{"domain":"bitfire.nl"}
    }
  }' | jq .

echo "# Bulk check"
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":4,
    "method":"tools/call",
    "params":{
      "name":"check_for_sale_bulk",
      "arguments":{"domains":"example.nl,bitfire.nl,sidnlabs.nl"}
    }
  }' | jq .

echo "# Foutafhandeling testen (onbekende tool)"
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"doesnotexist","arguments":{}}}' | jq .

echo "# Ping"
curl -s -X POST https://forsalereg.sidnlabs.nl/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}' | jq .
  
