from flask import Flask, jsonify
from flask_cors import CORS

def add_swagger_docs(app):
    """Add Swagger/OpenAPI documentation to Flask app"""
    
    @app.route('/swagger.json')
    def swagger_spec():
        """OpenAPI 3.0 specification"""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "LLM-Augmented Honeypot API",
                "description": "REST API honeypot with AI-enhanced responses",
                "version": "2.1.0"
            },
            "servers": [
                {
                    "url": "http://localhost:5000",
                    "description": "Local honeypot server"
                }
            ],
            "paths": {
                "/": {
                    "get": {
                        "summary": "Root endpoint",
                        "description": "Returns API information and available endpoints",
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "status": {"type": "string"},
                                                "message": {"type": "string"},
                                                "endpoints": {"type": "array"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/api/users": {
                    "get": {
                        "summary": "List users",
                        "description": "Returns list of users in the system",
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "success": {"type": "boolean"},
                                                "data": {"type": "array"},
                                                "total": {"type": "integer"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/api/search": {
                    "get": {
                        "summary": "Search endpoint",
                        "description": "Search functionality (vulnerable to SQLi for honeypot testing)",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "description": "Search query",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "500": {"description": "Database error (SQLi detected)"}
                        }
                    }
                },
                "/api/login": {
                    "post": {
                        "summary": "Login endpoint",
                        "description": "User authentication",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Login successful"},
                            "401": {"description": "Invalid credentials"}
                        }
                    }
                },
                "/api/admin/settings": {
                    "get": {
                        "summary": "Admin settings",
                        "description": "Administrative settings (requires authentication)",
                        "responses": {
                            "200": {"description": "Settings retrieved"},
                            "403": {"description": "Forbidden - admin access required"}
                        }
                    }
                }
            }
        }
        return jsonify(spec)
    
    @app.route('/api-docs')
    def swagger_ui():
        """Swagger UI HTML page"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Honeypot API Documentation</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
        </head>
        <body>
            <div id="swagger-ui"></div>
            <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
            <script>
                window.onload = function() {
                    SwaggerUIBundle({
                        url: '/swagger.json',
                        dom_id: '#swagger-ui',
                        presets: [
                            SwaggerUIBundle.presets.apis,
                            SwaggerUIBundle.SwaggerUIStandalonePreset
                        ]
                    });
                };
            </script>
        </body>
        </html>
        """
        return html