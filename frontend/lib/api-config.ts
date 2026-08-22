/**
 * API Configuration for Telegram Supervisor Bot
 * Uses NEXT_PUBLIC_API_URL environment variable
 */

export const getApiUrl = (): string => {
  // En desarrollo, usar localhost
  // En producción, usar la URL de Render desde variables de entorno
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'
  return apiUrl.replace(/\/$/, '') // Remove trailing slash if present
}

export const getTelegramEndpoints = () => {
  const baseUrl = getApiUrl()
  return {
    baseUrl,
    status: `${baseUrl}/api/v1/telegram/status`,
    sendAlert: `${baseUrl}/api/v1/telegram/send-alert`,
    alerts: {
      recent: (limit?: number) => `${baseUrl}/api/v1/telegram/alerts/recent${limit ? `?limit=${limit}` : ''}`,
      pending: (limit?: number) => `${baseUrl}/api/v1/telegram/alerts/pending${limit ? `?limit=${limit}` : ''}`,
    },
    approvals: {
      pending: `${baseUrl}/api/v1/telegram/approvals/pending`,
    },
    report: {
      daily: `${baseUrl}/api/v1/telegram/report/daily`,
    },
  }
}

export const sendAlert = async (payload: {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  content_preview: string
  threats: string[]
  threat_score: number
  source: string
}) => {
  const endpoints = getTelegramEndpoints()
  
  try {
    const response = await fetch(endpoints.sendAlert, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    })
    
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    
    return await response.json()
  } catch (error) {
    console.error('Failed to send alert:', error)
    throw error
  }
}

export const getBotStatus = async () => {
  const endpoints = getTelegramEndpoints()
  
  try {
    const response = await fetch(endpoints.status)
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to get bot status:', error)
    throw error
  }
}
