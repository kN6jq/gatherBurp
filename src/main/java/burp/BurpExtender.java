package burp;


import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import burp.bean.Config;
import burp.ui.*;
import burp.utils.*;

import static burp.dao.ConfigDAO.getToolConfig;
import static burp.utils.Utils.*;


public class BurpExtender  implements IBurpExtender, IContextMenuFactory{

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        MainUI mainUi = new MainUI(iBurpExtenderCallbacks);
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        Utils.callbacks.setExtensionName(Utils.name);
        Utils.callbacks.registerContextMenuFactory(this);
        Utils.callbacks.addSuiteTab(mainUi);
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Utils.callbacks.customizeUiComponent(mainUi);
            }
        });
        Utils.stdout.println("Loaded " + Utils.name + " v" + Utils.version + " by " + Utils.author);
        Utils.stdout.println("Happy Hacking :)");

    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        IHttpRequestResponse[] responses = iContextMenuInvocation.getSelectedMessages();
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation.getSelectedMessages()[0];
        JMenu fastjson = new JMenu("FastJson");
        JMenuItem Dnslog = new JMenuItem("FastJson Dnslog Check");
        Dnslog.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastJsonUI().CheckDnslog(responses);
                    }
                });
                thread.start();

            }
        });
        fastjson.add(Dnslog);

        JMenuItem Echo = new JMenuItem("FastJson Echo Check");
        Echo.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastJsonUI().CheckEchoVul(responses);
                    }
                });
                thread.start();

            }
        });
        fastjson.add(Echo);

        JMenuItem JNDI = new JMenuItem("FastJson JNDI Check");
        JNDI.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastJsonUI().CheckJNDIVul(responses);
                    }
                });
                thread.start();

            }
        });
        fastjson.add(JNDI);

        JMenuItem auth = new JMenuItem("AuthBypass Check");
        auth.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new AuthUI().CheckAuthBypass(responses);
                    }
                });
                thread.start();

            }
        });

        JMenuItem perm = new JMenuItem("PermBypass Check");
        perm.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new PermUI().CheckPermBypass(responses);
                    }
                });
                thread.start();

            }
        });

        JMenuItem sqli = new JMenuItem("SQLi Check");
        sqli.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new SqlUI().CheckSQLi(responses);
                    }
                });
                thread.start();

            }
        });


        JMenu tools = new JMenu("tools");
        List<Config> toolParam = getToolConfig();
        for (Config config : toolParam) {
            if (!Objects.equals(config.getType(), "") && !Objects.equals(config.getValue(), "")){
                tools.add(new JMenuItem(new AbstractAction(config.getType()) {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Runnable toolRunner = new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    RobotInput ri = new RobotInput();
                                    if (responses != null) {
                                        String cmd = config.getValue();
                                        if (cmd.contains("{url}")) {
                                            String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
                                            cmd = cmd.replace("{url}", url);
                                        } else if (cmd.contains("{request}")) {
                                            IHttpRequestResponse message = baseRequestResponse;
                                            String requestFilePath = RequestToFile(message);
                                            cmd = cmd.replace("{request}", requestFilePath);
                                        } else if (cmd.contains("{host}")) {
                                            IHttpRequestResponse message = baseRequestResponse;
                                            String host = message.getHttpService().getHost();
                                            cmd = cmd.replace("{host}", host);
                                        }
                                        ri.inputString(cmd);
                                    }
                                } catch (Exception e1) {
                                    e1.printStackTrace(stderr);
                                }
                            }
                        };
                        new Thread(toolRunner).start();
                    }
                }));
            }
        }


        listMenuItems.add(fastjson);
        listMenuItems.add(auth);
        listMenuItems.add(perm);
        listMenuItems.add(sqli);
        listMenuItems.add(tools);

        return listMenuItems;
    }




}