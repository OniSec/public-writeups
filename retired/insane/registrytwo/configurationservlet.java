package com.htb.hosting.services;

import com.htb.hosting.utils.Constants;
import com.htb.hosting.utils.config.Settings;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "reconfigure", value = {"/reconfigure"})
/* loaded from: ConfigurationServlet.class */
public class ConfigurationServlet extends AbstractServlet {
    private static final long serialVersionUID = -2336661269816738483L;

    @Override // javax.servlet.http.HttpServlet
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (!checkManager(request, response)) {
            return;
        }
        RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
        rd.include(request, response);
    }

    @Override // javax.servlet.http.HttpServlet
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (!checkManager(request, response)) {
            return;
        }
        Map<String, String> parameterMap = new HashMap<>();
        request.getParameterMap().forEach(k, v -> {
            parameterMap.put(k, v[0]);
        });
        Settings.updateBy(parameterMap);
        RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
        request.setAttribute("message", "Settings updated");
        rd.include(request, response);
    }

    private static boolean checkManager(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean isManager = request.getSession().getAttribute(Constants.S_IS_USER_ROLE_MGR) != null;
        if (!isManager) {
            response.sendRedirect(request.getContextPath() + "/panel");
        }
        return isManager;
    }

    @Override // javax.servlet.GenericServlet, javax.servlet.Servlet
    public void destroy() {
    }